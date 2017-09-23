##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'open3'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Nmap based Port Scanner',
      'Description' => %q{
        Use the Nmap security scanner to discover services on hosts on a computer network.
        This module requires the Nmap binary to be present on the source machine and may
        need administrative privileges depending on the arguments utilised.
      },
      'Author'      => 'Sion Dafydd <sion.dafydd[at]gmail.com>',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('PORTS', [ true, 'Ports to scan (e.g. 22-25,80,110-900)', '1-1023' ]),
        OptString.new('ARGS', [ false, 'Arguments to pass to Nmap', '-Pn -n -v -sV' ]),
        OptBool.new('SAVE_XML', [ true, 'Save Nmap XML log file', true ]),
      ], self.class
    )
  end

  def run_host(ip)
    if datastore['PORTS'].nil? or datastore['PORTS'].empty?
      raise Msf::OptionValidateError.new(['PORTS'])
    end

    # Get Nmap binary path
    cmd_bin = cmd_get_path
    raise RuntimeError 'Cannot locate nmap binary' unless cmd_bin

    begin
      # Get path to log file
      outfile = Rex::Quickfile.new("nmap-")
      if Rex::Compat.is_cygwin and cmd_bin =~ /cygdrive/i
        outfile_path = Rex::Compat.cygwin_to_win32(outfile.path)
      else
        outfile_path = outfile.path
      end

      # Build Nmap command
      cmd = [cmd_bin]
      cmd << "-oX #{outfile_path}"
      cmd << "-p \"#{datastore['PORTS']}\""
      cmd << "#{datastore['ARGS']}" if datastore['ARGS']
      cmd << ip

      # Execute
      run_cmd cmd.join(' ')

      # Check output
      if outfile.size.zero?
        print_error 'Output file is empty, no useful results can be processed.'
      else
        # Process output
        if framework.db and framework.db.active
          framework.db.import_nmap_xml_file(:filename => outfile_path)
        end
        # Save output
        nmap_save outfile if datastore['SAVE_XML']
      end
    ensure
      outfile.close
      outfile.unlink
    end
  end

  def cmd_get_path
    ret = Rex::FileUtils.find_full_path('nmap') || Rex::FileUtils.find_full_path('nmap.exe')
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
      print_status("Starting Nmap with pid #{pid}")
      print_status
      print_status("# #{command}")
      print_status
      output_threads = []

      output_threads << framework.threads.spawn("Module(#{self.refname})-#{pid}-stdout", false, pipe[1]) do |out_pipe|
        out_pipe.each_line do |cmd_out|
          if datastore['VERBOSE']
            print_status("#{cmd_out.chomp}")
          elsif cmd_out =~ /^Discovered open port /
            port, proto, ip = cmd_out.match(/^Discovered open port (\d+)\/(\w{3}) on (.+)$/).captures
            print_status("#{ip}:#{port} - #{proto.upcase} OPEN")
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

  def nmap_save(outfile)
    nmap_data = outfile.read(outfile.stat.size)
    saved_path = store_local('nmap.scan.xml', 'text/xml', nmap_data, "nmap_#{(Time.now.utc.to_f * 1000).to_i}.xml")
    print_status("Saved Nmap XML results to #{saved_path}")
  end
end
