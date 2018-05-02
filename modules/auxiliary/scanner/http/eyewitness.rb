##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Report

  def initialize
    super(
        'Name'   		  => 'Take website screenshots using Eyewitness',
        'Description'	=> %q{
          Use the Eyewitness tool to take screenshots of the webpages.
          This module requires the eyewitness binary to be present on the source machine.
        },
        'Author' 		  => 'Sion Dafydd <sion.dafydd[at]gmail.com>',
        'License'		  => BSD_LICENSE
    )

    register_options(
        [
            Opt::RHOST,
            Opt::RPORT(80),
            OptString.new('VHOST', [ false, "HTTP server virtual host" ]),
            OptBool.new('SSL', [ false, 'Negotiate SSL/TLS for outgoing connections', false]),
            OptString.new('PATH', [ true, 'Test base path', '/'])
        ]
    )

    deregister_options('RHOSTS')
  end

  def vhost
    datastore['VHOST'] || datastore['RHOST']
  end

  def rhost
    datastore['RHOST']
  end

  def rport
    datastore['RPORT']
  end

  def ssl
    datastore['SSL']
  end

  def cmd_get_path
    ret = Rex::FileUtils.find_full_path('eyewitness')
    return nil unless ret

    fullpath = ::File.expand_path(ret)
    if fullpath =~ /\s/ # Thanks, "Program Files"
      fullpath = "\"#{fullpath}\""
    end
    return fullpath
  end

  def run
    # Get eyewitness binary path
    cmd_bin = cmd_get_path
    raise RuntimeError 'Cannot locate eyewitness binary' unless cmd_bin

    # Create path to screenshot file
    outfile = Rex::Quickfile.new("eyewitness-")
    if Rex::Compat.is_cygwin and cmd_bin =~ /cygdrive/i
      outfile_path = Rex::Compat.cygwin_to_win32(outfile.path)
    else
      outfile_path = outfile.path
    end

    url = "#{(ssl ? 'https' : 'http')}://#{rhost}:#{rport}#{datastore['PATH']}"

    # Build Hydra command
    cmd = [cmd_bin]
    cmd << '--web'
    cmd << '--headless'
    cmd << "--vhost-name #{vhost}"
    cmd << "--single #{url}"

    # Execute
    run_cmd cmd.join(' ')
  end

  def run_cmd(command)
    begin
      pipe = ::Open3::popen3(command)
      pid = pipe.last.pid
      print_status("Starting eyewitness with pid #{pid}")
      print_status
      print_status("# #{command}")
      print_status
      output_threads = []

      output_threads << framework.threads.spawn("Module(#{self.refname})-#{pid}-stdout", false, pipe[1]) do |out_pipe|
        print_status("#{cmd_out.chomp}")
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
end
