# Original work Copyright (c) 2016, Carlos Perez <carlos_perez[at]darkoperator.com>
# Modified work Copyright (c) 2017 Sion Dafydd <sion.dafydd[at]gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted
# provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions and
# the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions
# and the following disclaimer in the documentation and/or other materials provided with the
# distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

module Msf
class Plugin::Discover < Msf::Plugin
  class DiscoverCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    # Set name for command dispatcher
    def name
      'Discover'
    end


    # Define Commands
    def commands
      {
          'discover_services' => 'Discover services on hosts by using nmap',
          'discover_version' => 'Enumerate version information from select services in the database',
          'discover_enumerate' => 'Enumerate information from select services in the database',
          'discover_login' => 'Perform login dictionary attacks against select services in the database',
          'pivot_show_networks' => 'List networks that can be pivoted through active sessions',
          'pivot_discover_hosts' => 'Discover hosts accessible through an active session',
          'pivot_discover_services' => 'Discover services on hosts in the database accessible through an active session'
      }
    end


    ##############################
    ########## COMMANDS ##########
    ##############################


    def cmd_discover_services(*args)
      # Variables
      scan_type = 'TCP'
      range = ''
      maxjobs = 30
      verbose = false
      port_lists = []

      # Define options
      opts = Rex::Parser::Arguments.new(
          '-r' => [true,  'IP addresses to scan [in CIDR notation or nmap format]'],
          '-u' => [false, 'Perform an UDP portscan instead of a TCP portscan [must be ran as root]'],
          '-p' => [true,  'Comma separated list of ports and/or port ranges to scan [ignored by UDP scan]'],
          '-h' => [true,  'Help']
      )

      if args.length == 0
        print_line opts.usage
        return
      end

      opts.parse(args) do |opt, idx, val|
        case opt
          when '-r'
            # Make sure no spaces are in the range definition
            range = val.gsub(' ', '')
          when '-u'
            scan_type = 'UDP'
          when '-p'
            port_lists = port_lists + Rex::Socket.portspec_crack(val)
          when '-h'
            print_line opts.usage
            return
        end
      end

      # Static UDP port list
      udp_ports = [53, 67, 137, 161, 123, 138, 139, 500, 523, 1434, 1604, 5093]

      # Check that the range is a valid one
      ip_list = Rex::Socket::RangeWalker.new(range)
      ips_given = []
      if ip_list.length == 0
        print_error('The IP addresses provided appear to be invalid.')
      else
        ip_list.each do |i|
          ips_given << i
        end
      end

      # Get the list of IP addresses that are routed through a pivot
      route_ips = _get_routed_ips
      if (ips_given.any? { |ip| route_ips.include?(ip) })
        print_error('You are trying to scan through a pivot, please use the \'pivot_discover_services\' command instead')
        return
      end

      if port_lists.length > 0
        ports = port_lists
      else
        # Generate port list that are supported by modules in Metasploit
        ports = _get_tcp_port_list
      end

      # Get a list of all services before the scan starts
      current_services = framework.db.workspace.services.where(state: 'open')

      # Run an nmap scan, this will populate the database with the hosts and services
      if scan_type =~ /TCP/
        cmd_str = "-Pn -sS -O -sV --version-all --script=default --traceroute -T4 -p #{ports * ','} --max-rtt-timeout=500ms --initial-rtt-timeout=200ms --min-rtt-timeout=200ms --open --stats-every 5s #{range}"
        print_status("Running nmap with options: #{cmd_str}")
        driver.run_single("db_nmap --save #{cmd_str}")
      else
        cmd_str = "-Pn -sU -T4 -p #{udp_ports * ','} --max-rtt-timeout=500ms --initial-rtt-timeout=200ms --min-rtt-timeout=200ms --open --stats-every 5s #{range}"
        print_status("Running nmap with options: #{cmd_str}")
        driver.run_single("db_nmap --save #{cmd_str}")
      end

      # Get a list of all services and extract new services
      after_services = framework.db.workspace.services.where(state: 'open')
      new_services = after_services - current_services
      print_good("#{new_services.count} new services found:")
      new_services.each do |service|
        print_good("\t#{service.host.address}:#{service.port}/#{service.proto}")
      end
    end


    def cmd_discover_version(*args)
      # Variables
      range = []
      filter = []
      smb_user = nil
      smb_pass = nil
      smb_dom = 'WORKGROUP'
      maxjobs = 30
      verbose = false

      # Define options
      opts = Rex::Parser::Arguments.new(
          '-r' => [true,  'Filter database hosts based on IP address [in CIDR notation or nmap format]'],
          '-u' => [true,  'SMB username for discovery [optional]'],
          '-p' => [true,  'SMB password for discovery [optional]'],
          '-d' => [true,  'SMB domain for discovery [optional]'],
          '-j' => [true,  'Max number of concurrent jobs [default: 30]'],
          '-v' => [false, 'Be Verbose when running jobs'],
          '-h' => [false, 'Help']
      )

      opts.parse(args) do |opt, idx, val|
        case opt
          when '-r'
            range = val
          when '-U'
            smb_user = val
          when '-P'
            smb_pass = val
          when '-D'
            smb_dom = val
          when '-j'
            maxjobs = val.to_i
          when '-v'
            verbose = true
          when '-h'
            print_line opts.usage
            return
        end
      end

      # generate a list of IP addresses to filter
      Rex::Socket::RangeWalker.new(range).each do |i|
        filter << i
      end

      framework.db.workspace.hosts.each do |h|
        if filter.empty? or filter.include?(h.address)
          # Run the discovery modules for the services of each host
          _run_version_scans(h.services.where(state: 'open'), smb_user, smb_pass, smb_dom, maxjobs, verbose)
        end
      end
    end


    def cmd_discover_enumerate(*args)
      # Variables
      range = []
      filter = []
      smb_user = nil
      smb_pass = nil
      smb_dom = 'WORKGROUP'
      maxjobs = 30
      verbose = false

      # Define options
      opts = Rex::Parser::Arguments.new(
          '-r' => [true,  'Filter database hosts based on IP address [in CIDR notation or nmap format]'],
          '-u' => [true,  'SMB username for discovery [optional]'],
          '-p' => [true,  'SMB password for discovery [optional]'],
          '-d' => [true,  'SMB domain for discovery [optional]'],
          '-j' => [true,  'Max number of concurrent jobs [default: 30]'],
          '-v' => [false, 'Be Verbose when running jobs'],
          '-h' => [false, 'Help']
      )

      opts.parse(args) do |opt, idx, val|
        case opt
          when '-r'
            range = val
          when '-u'
            smb_user = val
          when '-p'
            smb_pass = val
          when '-d'
            smb_dom = val
          when '-j'
            maxjobs = val.to_i
          when '-v'
            verbose = true
          when '-h'
            print_line opts.usage
            return
        end
      end

      # generate a list of IP addresses to filter
      Rex::Socket::RangeWalker.new(range).each do |i|
        filter << i
      end

      framework.db.workspace.hosts.each do |h|
        if filter.empty?
          _run_enumeration_scans(h.services.where(state: 'open'), smb_user, smb_pass, smb_dom, maxjobs, verbose)
        else
          if filter.include?(h.address)
            # Run the discovery modules for the services of each host
            _run_enumeration_scans(h.services.where(state: 'open'), smb_user, smb_pass, smb_dom, maxjobs, verbose)
          end
        end
      end
    end


    def cmd_discover_login(*args)
      # Variables
      range = []
      filter = []
      username = ''
      password = ''
      userfile = ''
      passfile = ''
      blank_passwords = false
      user_as_pass = false
      threads = 25
      maxjobs = 10
      verbose = false

      # Define options
      opts = Rex::Parser::Arguments.new(
          '-r' => [true,  'Filter database hosts based on IP address [in CIDR notation or nmap format]'],
          '-u' => [true,  'Username for login attempt [optional]'],
          '-p' => [true,  'Password for login attempt [optional]'],
          '-U' => [true,  'Load usernames from a file for login attempts [optional]'],
          '-P' => [true,  'Load passwords from a file for login attempts [optional]'],
          '-n' => [true,  'Try blank/null password for all users [optional]'],
          '-s' => [true,  'Try the username as the password for all users [optional]'],
          '-t' => [true,  'Max number of threads per job [default: 25]'],
          '-j' => [true,  'Max number of concurrent jobs [default: 10]'],
          '-v' => [false, 'Be Verbose when running jobs'],
          '-h' => [false, 'Help']
      )

      opts.parse(args) do |opt, idx, val|
        case opt
          when '-r'
            range = val
          when '-u'
            username = val
          when '-p'
            password = val
          when '-U'
            userfile = val
            if not ::File.exists?(userfile)
              print_error 'Username file does not exist!'
              return
            end
          when '-P'
            passfile = val
            if not ::File.exists?(passfile)
              print_error 'Password file does not exist!'
              return
            end
          when '-n'
            blank_passwords = val
          when '-s'
            user_as_pass = val
          when '-t'
            threads = val
          when '-j'
            maxjobs = val.to_i
          when '-v'
            verbose = true
          when '-h'
            print_line opts.usage
            return
        end
      end

      # generate a list of IP addresses to filter
      Rex::Socket::RangeWalker.new(range).each do |i|
        filter << i
      end

      framework.db.workspace.hosts.each do |h|
        if filter.empty?
          _run_login_scans(h.services.where(state: 'open'), username, password, userfile, passfile, blank_passwords, user_as_pass, threads, maxjobs, verbose)
        else
          if filter.include?(h.address)
            # Run the discovery modules for the services of each host
            _run_login_scans(h.services.where(state: 'open'), username, password, userfile, passfile, blank_passwords, user_as_pass, threads, maxjobs, verbose)
          end
        end
      end
    end


    def command_pivot_discover_hosts(*args)
      #option variables
      session_id = nil
      verbose = false

      opts = Rex::Parser::Arguments.new(
          '-s' => [true,  'Session to use for host discovery'],
          '-v' => [false, 'Be verbose and show pending actions'],
          '-h' => [false, 'Help Message']
      )

      opts.parse(args) do |opt, idx, val|
        case opt
          when '-s'
            session_id = val.to_i
          when '-v'
            verbose = true
          when '-h'
            print_line(opts.usage)
            return
          else
            print_line(opts.usage)
            return
        end
      end

      if session_id.nil?
        print_error('You need to specify a session to conduct a discovery against')
        print_line(opts.usage)
        return
      end


      if not framework.sessions.keys.include?(session_id.to_i)
        print_error('The session specified does not exist')
        return
      end

      # Get session object
      session = framework.sessions.get(session_id.to_i)

      if (session.type == 'meterpreter')
        # Collect addresses to help determine the best method for discovery
        int_addrs = []
        session.net.config.interfaces.each do |i|
          int_addrs = int_addrs + i.addrs
        end

        # Variable to hold the array of networks that we will discover
        networks = []

        print_status('Identifying networks accessible via session')
        session.net.config.each_route do |route|
          # Remove multicast and loopback interfaces
          next if route.subnet =~ /^(224\.|127\.)/
          next if route.subnet == '0.0.0.0'
          next if route.netmask == '255.255.255.255'

          # Save the network in to CIDR format
          networks << "#{route.subnet}/#{Rex::Socket.addr_atoc(route.netmask)}"
        end

        # Collect current set of hosts before the scan
        current_hosts = framework.db.workspace.hosts.where(state: 'alive')

        # Run ARP Scan and Ping Sweep for each of the networks
        networks.each do |n|
          opt = {'RHOSTS' => n}
          net_ips = []
          Rex::Socket::RangeWalker.new(n).each { |i| net_ips << i }
          # Check if any of the networks are directly connected. If so use ARP Scanner
          if int_addrs.any? { |ip| net_ips.include?(ip) }
            print_status("Performing an arp scan against #{n} network")
            _run_post_module(session_id, 'windows/gather/arp_scanner', opt, verbose)
          else
            print_status("Performing a ping sweep against #{n} network")
            _run_post_module(session_id, 'multi/gather/ping_sweep', opt, verbose)
          end
        end

        # See what hosts where discovered via the ping scan and ARP Scan
        after_hosts = framework.db.workspace.hosts.where(state: 'alive')
        new_hosts = after_hosts - current_hosts
        print_good("#{new_hosts.count} new hosts found:")
        hosts = new_hosts.map { |h| h.address }
        hosts.each do |host|
          print_good("\t#{host}")
        end
      end
    end


    def cmd_pivot_discover_services(*args)
      #option variables
      session_id = nil
      range = []
      filter = []
      port_scan = false
      udp_scan = false
      verbose = false
      port_lists = []

      opts = Rex::Parser::Arguments.new(
          '-r' => [true,  'Filter database hosts based on IP address [in CIDR notation or nmap format]'],
          '-s' => [true,  'Session to use for discovery of services'],
          '-t' => [false, 'Perform a TCP portscan'],
          '-u' => [false, 'Perform an UDP portscan'],
          '-p' => [true,  'Comma separated list of ports and/or port ranges to scan [ignored by UDP scan]'],
          '-v' => [false, 'Be verbose and show pending actions'],
          '-h' => [false, 'Help Message']
      )

      opts.parse(args) do |opt, idx, val|
        case opt
          when '-r'
            range = val
          when '-s'
            session_id = val.to_i
          when '-t'
            port_scan = true
          when '-u'
            udp_scan = true
          when '-v'
            verbose = true
          when '-p'
            port_lists = port_lists + Rex::Socket.portspec_crack(val)
          when '-h'
            print_line(opts.usage)
            return
          else
            print_line(opts.usage)
            return
        end
      end

      if not port_scan or not udp_scan
        print_error('You need to specify a portscan type.')
        print_line(opts.usage)
        return
      end

      if session_id.nil?
        print_error('You need to specify a session to do discovery against.')
        print_line(opts.usage)
        return
      end

      if not framework.sessions.keys.include?(session_id.to_i)
        print_error('The session specified does not exist')
        return
      end

      # generate a list of IP addresses to filter
      Rex::Socket::RangeWalker.new(range).each do |i|
        filter << i
      end

      # Static UDP port list
      udp_ports = [53, 67, 123, 137, 138, 139, 161, 523, 1434, 1604, 5093]

      # Get session object
      session = framework.sessions.get(session_id.to_i)

      if (session.type == 'meterpreter')
        print_status('Identifying networks accessible via session')

        # Switchboard instance for routing
        sb = Rex::Socket::SwitchBoard.instance

        # Variable to hold the array of networks that we will discover
        networks = []

        # Gather networks, add routes if necessary
        session.net.config.each_route do |route|
          # Remove multicast and loopback interfaces
          next if route.subnet =~ /^(224\.|127\.)/
          next if route.subnet == '0.0.0.0'
          next if route.netmask == '255.255.255.255'

          # Save the network in to CIDR format
          networks << "#{route.subnet}/#{Rex::Socket.addr_atoc(route.netmask)}"
          if port_scan || udp_scan
            if not sb.route_exists?(route.subnet, route.netmask)
              print_status("Routing new subnet #{route.subnet}/#{route.netmask} through session #{session.sid}")
              sb.add_route(route.subnet, route.netmask, session)
            end
          end
        end

        # Retrieve all host IP addresses that exist within the database
        hosts_in_db = framework.db.workspace.hosts.map { |h| h.address }

        if port_scan
          if port_lists.length > 0
            ports = port_lists
          else
            # Generate port list that are supported by modules in Metasploit
            ports = _get_tcp_port_list
          end
        end

        # Get a list of all services before the scan starts
        current_services = framework.db.workspace.services.where(state: 'open')

        networks.each do |n|
          print_status("Performing portscans within #{n} network")

          # Filter hosts to scan based on network
          net_hosts = []
          Rex::Socket::RangeWalker.new(n).each { |i| net_hosts << i }
          found_ips = hosts_in_db & net_hosts

          # run portscan against hosts in this network
          if port_scan
            found_ips.each do |t|
              if filter.empty? or filter.include?(t)
                print_good("Running TCP portscan against #{t}")
                _run_aux_module('scanner/portscan/tcp', {'RHOSTS' => t,
                                                         'PORTS' => (ports * ','),
                                                         'THREADS' => 5,
                                                         'CONCURRENCY' => 50,
                                                         'ConnectTimeout' => 1})
                _jobwaiting(10, false, 'scanner')
              end
            end
          end

          # if a udp port scan was selected lets execute it
          if udp_scan
            found_ips.each do |t|
              if filter.empty? or filter.include?(t)
                print_good("Running UDP portscan against #{t}")
                _run_aux_module('scanner/discovery/udp_probe', {'RHOSTS' => t,
                                                                'PORTS' => (udp_ports * ','),
                                                                'THREADS' => 5})
                _jobwaiting(10, false, 'scanner')
              end
            end
          end

          # Wait for the scanners to finish
          if port_scan || udp_scan
            print_status('Waiting for scans to finish')
            finish_scanning = false
            while not finish_scanning
              ::IO.select(nil, nil, nil, 2.5)
              count = _get_job_count
              if verbose
                print_status("\t#{count} scans pending")
              end
              if count == 0
                finish_scanning = true
              end
            end
          end
        end

        # Get a list of all services and extract new services
        after_services = framework.db.workspace.services.where(state: 'open')
        new_services = after_services - current_services
        print_good("#{new_services.count} new services found:")
        new_services.each do |service|
          print_good("\t#{service.host.address}:#{service.port}/#{service.proto}")
        end
      end
    end


    def cmd_pivot_show_networks(*args)
      #option variables
      session_list = nil
      opts = Rex::Parser::Arguments.new(
          '-s' => [true,  'Sessions to enumerate networks against [Example: <all> or <1,2,3,4>]'],
          '-h' => [false, 'Help Message']
      )

      opts.parse(args) do |opt, idx, val|
        case opt
          when '-s'
            if val =~ /all/i
              session_list = framework.sessions.keys
            else
              session_list = val.split(',')
            end
          when '-h'
            print_line('This command will show the networks that can be routed through a Meterpreter session.')
            print_line(opts.usage)
            return
          else
            print_line('This command will show the networks that can be routed through a Meterpreter session.')
            print_line(opts.usage)
            return
        end
      end
      tbl = Rex::Ui::Text::Table.new('Columns' => %w(Network Netmask Session))
      # Go through each sessions specified
      session_list.each do |si|
        # Check that session actually exists
        if framework.sessions.keys.include?(si.to_i)
          # Get session object
          session = framework.sessions.get(si.to_i)
          # Check that it is a Meterpreter session
          if (session.type == 'meterpreter')
            session.net.config.each_route do |route|
              # Remove multicast and loopback interfaces
              next if route.subnet =~ /^(224\.|127\.)/
              next if route.subnet == '0.0.0.0'
              next if route.netmask == '255.255.255.255'
              tbl << [route.subnet, route.netmask, si]
            end
          end
        end
      end
      print_line(tbl.to_s)
    end


    #############################
    ########## PRIVATE ##########
    #############################

    # Get a list of IP addresses that are routed through a Meterpreter sessions
    # Note: This one bit me hard!! in testing. Make sure that the proper module is ran against the proper host
    def _get_routed_ips
      routed_ips = []
      pivot = Rex::Socket::SwitchBoard.instance
      unless (pivot.routes.to_s == '') || (pivot.routes.to_s == '[]')
        pivot.routes.each do |r|
          sn = r.subnet
          nm = r.netmask
          cidr = Rex::Socket.addr_atoc(nm)
          pivot_ip_range = Rex::Socket::RangeWalker.new("#{sn}/#{cidr}")
          pivot_ip_range.each do |i|
            routed_ips << i
          end
        end
      end
      return routed_ips
    end


    # Generate an up to date list of ports used by auxiliary and exploit modules
    def _get_tcp_port_list
      # UDP ports
      udp_ports = [53, 67, 137, 161, 123, 138, 139, 1434]

      # Ports missing by the autogen
      additional_ports = [465, 587, 995, 993, 5433, 50001, 50002, 1524, 6697, 8787, 41364, 48992, 49663, 59034]

      print_status('Generating list of ports used by Auxiliary Modules')
      ap = (framework.auxiliary.collect { |n, e| x=e.new; x.datastore['RPORT'].to_i }).compact
      print_status('Generating list of ports used by Exploit Modules')
      ep = (framework.exploits.collect { |n, e| x=e.new; x.datastore['RPORT'].to_i }).compact

      # Join both list removing the duplicates
      port_list = (((ap | ep) - [0, 1]) - udp_ports) + additional_ports
      return port_list
    end


    # Run version auxiliary modules depending on whether version information exists or not
    def _run_version_scans(services, smb_user, smb_pass, smb_dom, maxjobs, verbose)
      # Run version scan on discovered services
      services.each do |s|
        if (s.port == 445) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'SMBUser' => smb_user, 'SMBPass' => smb_pass,
                  'SMBDomain' => smb_dom}
          _run_aux_module('scanner/smb/smb_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'http' or s.port == 80) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/http/http_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /https/ or s.port == 443) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port, 'SSL' => true}
          _run_aux_module('scanner/http/http_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /https/i or s.port == 443) and s.info.to_s =~ /vmware/i
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port, 'SSL' => true}
          _run_aux_module('scanner/vmware/esx_fingerprint', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'ftp' or s.port == 21) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/ftp/ftp_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'telnet' or s.port == 23) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/telnet/telnet_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /vmware-auth|vmauth/ or s.port == 902) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/vmware/vmauthd_version)', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'ssh' or s.port == 22) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/ssh/ssh_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /smpt|smtps/ or s.port.to_s =~/25|465|587/) and s.info.to_s == ''
          if s.port == 465 or s.name.to_s == 'smtps'
            opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port, 'SSL' => true}
          else
            opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          end
          _run_aux_module('scanner/smtp/smtp_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /pop3|pop3s/ or s.port.to_s =~/110|995/) and s.info.to_s == ''
          if s.port == 995 or s.name.to_s == 'pop3s'
            opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port, 'SSL' => true}
          else
            opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          end
          _run_aux_module('scanner/pop3/pop3_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /imap|imaps/ or s.port.to_s =~/143|993/) and s.info.to_s == ''
          if s.port == 993 or s.name.to_s == 'imaps'
            opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port, 'SSL' => true}
          else
            opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          end
          _run_aux_module('scanner/imap/imap_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /mssql|ms-sql/ or s.port == 1433) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/mssql/mssql_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /postgres|postgresql/ or s.port.to_s =~/5432|5433/) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/postgres/postgres_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'mysql' or s.port == 3306) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/mysql/mysql_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /h323/ or s.port == 1720) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/h323/h323_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /jetdirect/i or s.port == 9100)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/printer/printer_version_info', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 623)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/ipmi/ipmi_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 1521) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/oracle/tnslsnr_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'wdbrpc' or s.port == 17185) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/vxworks/wdbrpc_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 50013) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/vxworks/wdbrpc_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port.to_s =~ /50000|50001|50002/) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/db2/db2_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port.to_s =~ /50013/) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/sap/sap_mgmt_con_version', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 8080) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/http/sap_businessobjects_version_enum', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'winrm' or s.port == 5985) and s.info.to_s == ''
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/winrm/winrm_auth_methods', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next
        end
      end
    end


    # Run enumeration auxiliary modules
    def _run_enumeration_scans(services, smb_user, smb_pass, smb_dom, maxjobs, verbose)
      # Run version scan by identified services
      services.each do |s|
        if (s.name.to_s == 'msrpc' or s.port == 135)
          opts = {'RHOSTS' => s.host.address}
          _run_aux_module('scanner/netbios/nbname', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')

        elsif (s.name.to_s == 'microsoft-ds' or s.port == 445)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'SMBUser' => smb_user, 'SMBPass' => smb_pass, 'SMBDomain' => smb_dom}
          _run_aux_module('scanner/smb/smb_enumusers', opts)
          _run_aux_module('scanner/smb/smb_enumshares', opts)
          _run_aux_module('scanner/smb/smb_lookupsid', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'http' or s.port == 80)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/http/title', opts)
          #_run_aux_module('scanner/http/robots_txt', opts)
          #_run_aux_module('scanner/http/open_proxy', opts)
          #_run_aux_module('scanner/http/webdav_scanner', opts)
          #_run_aux_module('scanner/http/http_put', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /https/ or s.port == 443)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port, 'SSL' => true}
          _run_aux_module('scanner/http/title', opts)
          #_run_aux_module('scanner/http/robots_txt', opts)
          #_run_aux_module('scanner/http/open_proxy', opts)
          #_run_aux_module('scanner/http/webdav_scanner', opts)
          #_run_aux_module('scanner/http/http_put', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /https/i or s.port == 443) and s.info.to_s =~ /vmware/i
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/vmware/esx_fingerprint', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'ftp' or s.port == 21)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/ftp/anonymous', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'ssh' or s.port == 22)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/ssh/fortinet_backdoor', opts)
          _run_aux_module('scanner/ssh/juniper_backdoor', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'telnet' or s.port == 23)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/telnet/telnet_encrypt_overflow', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'smtp' or s.port.to_s =~/25|465|587/)
          if s.port == 465
            opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port, 'SSL' => true}
          else
            opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          end
          _run_aux_module('scanner/smtp/smtp_enum', opts)
          _run_aux_module('scanner/smtp/smtp_ntlm_domain', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /afp/ or s.port == 548)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/afp/afp_server_info', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /vnc/i or s.port == 5900)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/vnc/vnc_none_auth', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /jetdirect/i || s.port == 9100)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/printer/printer_ready_message', opts)
          _run_aux_module('scanner/printer/printer_list_volumes', opts)
          _run_aux_module('scanner/printer/printer_list_dir', opts)
          _run_aux_module('scanner/printer/printer_download_file', opts)
          _run_aux_module('scanner/printer/printer_env_vars', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 623)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/ipmi/ipmi_cipher_zero', opts)
          _run_aux_module('scanner/ipmi/ipmi_dumphashes', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'rpcbind' or s.port == 111)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/nfs/nfsmount', opts)
          _run_aux_module('scanner/misc/sunrpc_portmapper', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'x11' or s.port == 6000)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/x11/open_x11', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 17185 or s.port == 50013)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/vxworks/wdbrpc_bootline', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 1521)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/oracle/tnspoison_checker', opts)
          _run_aux_module('scanner/oracle/sid_enum', opts)
          _run_aux_module('scanner/oracle/sid_brute', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'lsnr' or s.port == 1158)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/oracle/spy_sid', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port.to_s =~ /50013/)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/sap/sap_mgmt_con_getaccesspoints', opts)
          _run_aux_module('scanner/sap/sap_mgmt_con_extractusers', opts)
          _run_aux_module('scanner/sap/sap_mgmt_con_abaplog', opts)
          _run_aux_module('scanner/sap/sap_mgmt_con_getenv', opts)
          _run_aux_module('scanner/sap/sap_mgmt_con_getlogfiles', opts)
          _run_aux_module('scanner/sap/sap_mgmt_con_getprocessparameter', opts)
          _run_aux_module('scanner/sap/sap_mgmt_con_instanceproperties', opts)
          _run_aux_module('scanner/sap/sap_mgmt_con_listlogfiles', opts)
          _run_aux_module('scanner/sap/sap_mgmt_con_startprofile', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /proxy/i or s.port == 8080)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/http/open_proxy', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'couchdb' or s.port == 5984)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/couchdb/couchdb_enum', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'finger' or s.port == 79)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/finger/finger_users', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'mysql' or s.port == 3306)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/mysql/mysql_authbypass_hashdump', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /rmiregistry|java-rmi/i or s.port.to_s =~ /1098|1099/)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/misc/java_rmi_server', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 161 and s.proto == 'udp') or (s.name.to_s =~/snmp/)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port}
          _run_aux_module('scanner/snmp/snmp_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')

          if s.creds.length > 0
            s.creds.each do |c|
              opts = {
                  'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'VERSION' => '1', 'COMMUNITY' => c.pass
              }
              _run_aux_module('scanner/snmp/snmp_enum', opts)
              _jobwaiting(maxjobs, verbose, 'scanner')

              opts = {
                  'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'VERSION' => '2c', 'COMMUNITY' => c.pass
              }
              _run_aux_module('scanner/snmp/snmp_enum', opts)
              _jobwaiting(maxjobs, verbose, 'scanner')

              if s.host.os_name =~ /windows/i
                opts = {
                    'RHOSTS' => s.host.address, 'RPORT' => s.port,
                    'VERSION' => '1', 'COMMUNITY' => c.pass
                }
                _run_aux_module('scanner/snmp/snmp_enumusers', opts)
                _jobwaiting(maxjobs, verbose, 'scanner')

                opts = {
                    'RHOSTS' => s.host.address, 'RPORT' => s.port,
                    'VERSION' => '2c', 'COMMUNITY' => c.pass
                }
                _run_aux_module('scanner/snmp/snmp_enumusers', opts)
                _jobwaiting(maxjobs, verbose, 'scanner')

                opts = {
                    'RHOSTS' => s.host.address, 'RPORT' => s.port,
                    'VERSION' => '1', 'COMMUNITY' => c.pass
                }
                _run_aux_module('scanner/snmp/snmp_enumshares', opts)
                _jobwaiting(maxjobs, verbose, 'scanner')

                opts = {
                    'RHOSTS' => s.host.address, 'RPORT' => s.port,
                    'VERSION' => '2c', 'COMMUNITY' => c.pass
                }
                _run_aux_module('scanner/snmp/snmp_enumshares', opts)
                _jobwaiting(maxjobs, verbose, 'scanner')
              else
                opts = {
                    'RHOSTS' => s.host.address, 'RPORT' => s.port,
                    'VERSION' => '1', 'COMMUNITY' => c.pass
                }
                _run_aux_module('scanner/snmp/xerox_workcentre_enumusers', opts)
                _jobwaiting(maxjobs, verbose, 'scanner')

                opts = {
                    'RHOSTS' => s.host.address, 'RPORT' => s.port,
                    'VERSION' => '2c', 'COMMUNITY' => c.pass
                }
                _run_aux_module('scanner/snmp/xerox_workcentre_enumusers', opts)
                _jobwaiting(maxjobs, verbose, 'scanner')

                opts = {
                    'RHOSTS' => s.host.address, 'RPORT' => s.port,
                    'VERSION' => '1', 'COMMUNITY' => c.pass
                }
                _run_aux_module('scanner/snmp/aix_version', opts)
                _jobwaiting(maxjobs, verbose, 'scanner')

                opts = {
                    'RHOSTS' => s.host.address, 'RPORT' => s.port,
                    'VERSION' => '2c', 'COMMUNITY' => c.pass
                }
                _run_aux_module('scanner/snmp/aix_version', opts)
                _jobwaiting(maxjobs, verbose, 'scanner')
                next
              end
            end
          end
        end
      end
    end


    # Run login auxiliary modules
    def _run_login_scans(services, username, password, userfile, passfile, blank_passwords, user_as_pass, threads, maxjobs, verbose)
      # Run login scan by identified services
      services.each do |s|
        if (s.name.to_s == 'couchdb' or s.port == 5984)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERPASS_FILE' => nil,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'http_default_users.txt'),
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'http_default_pass.txt')})
          end
          _run_aux_module('scanner/couchdb/couchdb_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')

        elsif (s.name.to_s == 'ftp' or s.port == 21)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'unix_users.txt'),
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'adobe_top100_pass.txt')})
          end
          _run_aux_module('scanner/ftp/ftp_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'mongod' or s.port.to_s =~ /27017|27018|27019|28017/)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'unix_users.txt'),
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'adobe_top100_pass.txt')})
          end
          _run_aux_module('scanner/mongodb/mongodb_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /mssql|ms-sql/ or s.port == 1433)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USERNAME' => 'sa',
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'adobe_top100_pass.txt')})
          end
          _run_aux_module('scanner/mssql/mssql_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'mysql' or s.port == 3306)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USERNAME' => 'root',
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'adobe_top100_pass.txt')})
          end
          _run_aux_module('scanner/mysql/mysql_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif ((s.port == 5560 or s.port == 7777) and s.name.to_s == 'http')
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERPASS_FILE' => nil,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USERPASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists',
                                                      'oracle_default_userpass.txt')})
          end
          _run_aux_module('scanner/oracle/isqlplus_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')

        elsif (s.port == 1521)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERPASS_FILE' => nil,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USERPASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists',
                                                      'oracle_default_userpass.txt')})
          end
          _run_aux_module('scanner/oracle/oracle_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'pcanywheredata' or s.port == 5631)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USERNAME' => 'administrator',
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'adobe_top100_pass.txt')})
          end
          _run_aux_module('scanner/pcanywhere/pcanywhere_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /pop3|pop3s/ or s.port.to_s =~/110|995/)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'unix_users.txt'),
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'adobe_top100_pass.txt')})
          end
          opts.update('SSL' => true) if s.port == 995 or s.name.to_s == 'pop3s'
          _run_aux_module('scanner/pop3/pop3_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /postgres|postgresql/ or s.port.to_s =~/5432|5433/)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERPASS_FILE' => nil,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'postgres_default_user.txt'),
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'postgres_default_pass.txt')})
          end
          _run_aux_module('scanner/postgres/postgres_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'redis' or s.port == 6379)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'PASSWORD' => password, 'PASS_FILE' => passfile}
          if password.empty? and passfile.empty?
            # if no passwords have been specified, set defaults
            opts.update({'PASSWORD' => 'foobared'})
            opts.update({'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'adobe_top100_pass.txt')})
          end
          _run_aux_module('scanner/redis/redis_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 512)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'unix_users.txt'),
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'adobe_top100_pass.txt')})
          end
          _run_aux_module('scanner/rservices/rexec_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 513)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port, 'THREADS' => threads,
                  'FROMUSER' => username, 'FROMUSER_FILE' => userfile}
          if username.empty? and userfile.empty?
            # if no usernames have been specified, set defaults
            opts.update({'FROMUSER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'rservices_from_users.txt')})
          end
          _run_aux_module('scanner/rservices/rlogin_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 514)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port, 'THREADS' => threads,
                  'FROMUSER' => username, 'FROMUSER_FILE' => userfile}
          if username.empty? and userfile.empty?
            # if no usernames have been specified, set defaults
            opts.update({'FROMUSER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'rservices_from_users.txt')})
          end
          _run_aux_module('scanner/rservices/rsh_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 50013)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'sap_common.txt'),
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'adobe_top100_pass.txt')})
          end
          _run_aux_module('scanner/sap/sap_mgmt_con_brute_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.port == 161 and s.proto == 'udp') or (s.name.to_s =~/snmp/)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port, 'THREADS' => threads,
                  'PASSWORD' => username, 'PASS_FILE' => userfile}
          if password.empty? and passfile.empty?
            # if no passwords have been specified, set defaults
            opts.update({'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'snmp_default_pass.txt')})
          end
          _run_aux_module('scanner/snmp/snmp_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'ssh' or s.port == 22)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'unix_users.txt'),
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'adobe_top100_pass.txt')})
          end
          _run_aux_module('scanner/ssh/ssh_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s == 'telnet' or s.port == 23)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'unix_users.txt'),
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'adobe_top100_pass.txt')})
          end
          _run_aux_module('scanner/telnet/telnet_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /vmware-auth|vmauth/ or s.port == 902)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'USER_AS_PASS' => user_as_pass, 'THREADS' => threads,
                  'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => userfile, 'PASS_FILE' => passfile}
          if username.empty? and password.empty? and userfile.empty? and passfile.empty?
            # if no usernames or passwords have been specified, set defaults
            opts.update({'USER_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'http_default_users.txt'),
                         'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'http_default_pass.txt')})
          end
          _run_aux_module('scanner/vmware/vmauthd_login)', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next

        elsif (s.name.to_s =~ /vnc/i or s.port == 5900)
          opts = {'RHOSTS' => s.host.address, 'RPORT' => s.port,
                  'BLANK_PASSWORDS' => blank_passwords, 'THREADS' => threads,
                  'PASSWORD' => username, 'PASS_FILE' => userfile}
          if password.empty? and passfile.empty?
            # if no passwords have been specified, set defaults
            opts.update({'PASS_FILE' => File.join(Msf::Config.data_directory, 'wordlists', 'vnc_passwords.txt')})
          end
          _run_aux_module('scanner/vnc/vnc_login', opts)
          _jobwaiting(maxjobs, verbose, 'scanner')
          next
        end
      end
    end


    # Method for running auxiliary modules given the module name and options in a hash
    def _run_aux_module(mod, opts, as_job=true, verbose=false)
      m = framework.auxiliary.create(mod)
      if !m.nil?
        opts.each do |o, v|
          m.datastore[o] = v
        end
        m.options.validate(m.datastore)
        m.run_simple(
            'LocalInput' => driver.input,
            'LocalOutput' => driver.output,
            'RunAsJob' => as_job,
            'Quiet' => !verbose
        )
        print_status("running module auxiliary/#{mod} against #{opts['RHOSTS']}:#{opts['RPORT']}")
      else
        print_error("module auxiliary/#{mod} does not exist")
        return
      end
    end


    # Run Post Module against specified session and hash of options
    def _run_post_module(session, mod, opts, verbose=false)
      m = framework.post.create(mod)
      begin
        # Check that the module is compatible with the session specified
        if m.session_compatible?(session.to_i)
          m.datastore['SESSION'] = session.to_i
          # Process the option provided as a hash
          opts.each do |o, v|
            m.datastore[o] = v
          end
          # Validate the Options
          m.options.validate(m.datastore)
          # Inform what Post module is being ran
          print_status("Running #{mod} against #{session}")
          # Execute the Post Module
          m.run_simple(
              'LocalInput' => driver.input,
              'LocalOutput' => driver.output,
              'Quiet' => !verbose
          )
        end
      rescue
        print_error("Could not run post module against sessions #{session}")
      end
    end


    # Get the specific count of jobs which name contains a specified text
    def _get_job_count(type='scanner')
      job_count = 0
      framework.jobs.each do |k, j|
        if j.name =~ /#{type}/
          job_count = job_count + 1
        end
      end
      return job_count
    end


    # Wait for commands to finish
    def _jobwaiting(maxjobs, verbose, jtype)
      while (_get_job_count(jtype) >= maxjobs)
        ::IO.select(nil, nil, nil, 2.5)
        if verbose
          print_status('waiting for modules to finish')
        end
      end
    end
  end

  def initialize(framework, opts)
    super
    if framework.db and framework.db.active
      add_console_dispatcher(DiscoverCommandDispatcher)

      print_line 'Version 1.5'
      print_line 'Discover plugin loaded.'
    else
      print_error('This plugin requires the framework to be connected to a Database!')
    end
  end

  def cleanup
    remove_console_dispatcher('Discover')
  end

  def name
    'Discover'
  end

  def desc
    'Plugin for discovery automation.'
  end

  protected
end
end
