##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'open3'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
        'Name'        => 'Hydra based Login Scanner',
        'Description' => %q{
        Use the Hydra login cracker to guess credentials in use by services on a computer network.
        This module requires the Hydra binary to be present on the source machine and may
        need administrative privileges depending on the arguments utilised.
      },
        'Author'      => 'Sion Dafydd <sion.dafydd[at]gmail.com>',
        'License'     => MSF_LICENSE
    )

    register_options(
        [
            OptEnum.new('SERVICE', [ true, 'Service type', nil,
                                      [ 'adam6500', 'asterisk', 'afp', 'cisco', 'cisco-enable', 'cvs', 'firebird',
                                        'ftp', 'ftps', 'http-head', 'http-get', 'http-post', 'https-head', 'https-get',
                                        'https-post', 'http-get-form', 'http-post-form', 'https-get-form',
                                        'https-post-form', 'http-proxy', 'http-proxy-urlenum', 'icq', 'imap', 'imaps',
                                        'irc', 'ldap2', 'ldaps', 'ldap3', 'ldap3s', 'ldap3-crammd5', 'ldap3-digestmd5',
                                        'ldap3s-crammd5', 'ldap3s-digestmd5', 'mssql', 'mysql', 'nntp',
                                        'oracle-listener', 'oracle-sid', 'pcanywhere', 'pcnfs', 'pop3', 'pop3s',
                                        'postgres', 'radmin2', 'rdp', 'redis', 'rexec', 'rlogin', 'rpcap', 'rsh',
                                        'rtsp', 's7-300', 'sip', 'smb', 'smtp', 'smtps', 'smtp-enum', 'snmp', 'socks5',
                                        'ssh', 'sshkey', 'svn', 'teamspeak', 'telnet', 'telnets', 'vmauthd', 'vnc',
                                        'xmpp'] ]),
            OptPath.new('USERPASS_FILE',  [ false, 'File containing users and passwords separated by colon, one pair per line' ]),
            OptInt.new('TASKS', [ true, 'The number of parallel connections per host', 16 ]),
            Opt::RPORT,
            OptBool.new('REV_USER_AS_PASS', [ false, 'Try the username reversed as the password for all users', false ]),
            OptBool.new('LOOP_USERS', [ false, 'Loop around users instead of passwords', false ])
        ], self.class
    )

    deregister_options('BRUTEFORCE_SPEED', 'DB_ALL_CREDS', 'DB_ALL_USERS', 'DB_ALL_PASS',
                       'MaxGuessesPerService', 'MaxMinutesPerService', 'MaxGuessesPerUser')
  end

  def run_host(ip)
    if datastore['RPORT'].nil?
      raise Msf::OptionValidateError.new(['RPORT'])
    end

    # Verify option combinations
    if datastore['USER_FILE'] and (datastore['USERPASS_FILE'] or datastore['USERNAME'])
      raise RuntimeError 'Using both USER_FILE and USERPASS_FILE/USERNAME options is unsupported by Hydra'
    end

    if datastore['USER_FILE'] and datastore['USERNAME']
      raise RuntimeError 'Using both USER_FILE and USERNAME options is unsupported by Hydra'
    end

    if datastore['PASS_FILE'] and datastore['PASSWORD']
      raise RuntimeError 'Using both PASS_FILE and PASSWORD options is unsupported by Hydra'
    end

    # Get Hydra binary path
    cmd_bin = cmd_get_path
    raise RuntimeError 'Cannot locate hydra binary' unless cmd_bin

    # Build Hydra command
    cmd = [cmd_bin]
    if datastore['USERPASS_FILE']
      cmd << "-C #{datastore['USERPASS_FILE']}"
    else
      if datastore['USER_FILE']
        cmd << "-L #{datastore['USER_FILE']}"
      else
        cmd << "-l #{datastore['USERNAME']}"
      end
      if datastore['PASS_FILE']
        cmd << "-P #{datastore['PASS_FILE']}"
      else
        cmd << "-p #{datastore['PASSWORD']}"
      end
    end
    cmd << '-e n' if datastore['BLANK_PASSWORDS'] # try null password
    cmd << '-e s' if datastore['USER_AS_PASS']    # try login as password
    cmd << '-e r' if datastore['REV_USER_AS_PASS']     # try reversed login as password
    cmd << "-t #{datastore['TASKS']}"
    cmd << '-f' if datastore['STOP_ON_SUCCESS']   # exit when a login/pass pair is found
    cmd << '-u' if datastore['LOOP_USERS']        # loop around users, not passwords"
    cmd << '-V' if datastore['VERBOSE']           # verbose

    cmd << "#{datastore['SERVICE']}://#{ip}:#{datastore['RPORT']}"

    # Execute
    run_cmd cmd.join(' ')
  end

  def cmd_get_path
    ret = Rex::FileUtils.find_full_path('hydra') || Rex::FileUtils.find_full_path('hydra.exe')
    return nil unless ret

    fullpath = ::File.expand_path(ret)
    if fullpath =~ /\s/ # Thanks, "Program Files"
      fullpath = "\"#{fullpath}\""
    end
    return fullpath
  end

  def run_cmd(command)
    begin
      pipe = ::Open3::popen3(command)
      pid = pipe.last.pid
      print_status("Starting Hydra with pid #{pid}")
      print_status
      print_status("# #{command}")
      print_status
      output_threads = []

      output_threads << framework.threads.spawn("Module(#{self.refname})-#{pid}-stdout", false, pipe[1]) do |out_pipe|
        out_pipe.each_line do |cmd_out|
          if cmd_out =~ /^\[\d+\]\[.+\]\s+host:.*login:.*password:.*$/
            username, password = cmd_out.match(/^\[\d+\]\[.+\]\s+host:.*login:\s+(.*)\s+password:\s+(.*)$/).captures
            print_good("#{cmd_out.chomp}")

            report_cred(
                ip: datastore['RHOST'],
                port: datastore['RPORT'],
                service_name: datastore['SERVICE'],
                user: username,
                password: password
            )
          else
            print_status("#{cmd_out.chomp}")
          end
        end
      end

      output_threads << framework.threads.spawn("Module(#{self.refname})-#{pid}-stderr", false, pipe[2]) do |err_pipe|
        err_pipe.each_line do |cmd_err|
          print_error("#{cmd_err.chomp}")
        end
      end

      output_threads.map {|t| t.join rescue nil}
      pipe.each {|p| p.close rescue nil}
    rescue ::IOError => e
      print_error(e)
    end
  end

  def report_cred(opts)
    service_data = {
        address: opts[:ip],
        port: opts[:port],
        service_name: opts[:service_name],
        protocol: 'tcp',
        workspace_id: myworkspace_id
    }

    credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: opts[:user],
        private_data: opts[:password],
        private_type: :password
    }.merge(service_data)

    login_data = {
        last_attempted_at: Time.now,
        core: create_credential(credential_data),
        status: Metasploit::Model::Login::Status::SUCCESSFUL
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
