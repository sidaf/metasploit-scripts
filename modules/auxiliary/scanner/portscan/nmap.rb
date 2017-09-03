require 'msf/core'
require 'open3'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
        'Name'           => 'Nmap based Port Scanner',
        'Description'    => %q{
          Use the Nmap security scanner to discover services on hosts on a computer network.
          This module requires the Nmap binary to be present on the source machine and may
          need administrative privileges depending on the arguments utilised.
        },
        'Author'         => 'Sion Dafydd <sion.dafydd[at]gmail.com>',
        'License'        => MSF_LICENSE
    )

    register_options(
        [
            OptString.new('PORTS', [true, 'Ports to scan (e.g. 22-25,80,110-900)', '1-1023']),
            OptString.new('NMAP_ARGS', [false, 'Arguments to pass to Nmap', '-v']),
            OptBool.new('NMAP_VERBOSE', [ false, 'Display Nmap output', false]),
            OptBool.new('NMAP_SAVE', [ false, 'Save Nmap XML log file', true]),
        ], self.class)

  end

  def run_host(ip)
    ports = Rex::Socket.portspec_crack(datastore['PORTS'])

    if ports.empty?
      raise Msf::OptionValidateError.new(['PORTS'])
    end

    # Get Nmap binary path
    nmap_bin = nmap_get_path
    if not nmap_bin
      raise RuntimeError, 'Cannot locate nmap binary'
    end

    begin
      # Get path to log file
      outfile = Rex::Quickfile.new("nmap-")
      if Rex::Compat.is_cygwin and nmap_bin =~ /cygdrive/i
        outfile_path = Rex::Compat.cygwin_to_win32(outfile.path)
      else
        outfile_path = outfile.path
      end

      # Build Nmap command
      nmap_cmd = [nmap_bin]
      nmap_cmd << "-oX #{outfile_path}"
      nmap_cmd << "-p \"#{datastore['PORTS']}\""
      nmap_cmd << "#{datastore['NMAP_ARGS']}" if datastore['NMAP_ARGS']
      nmap_cmd << ip

      # Execute
      nmap_run nmap_cmd.join(" ")

      # Check output
      if not outfile.size.zero?
        # Process output
        framework.db.import_nmap_xml_file(:filename => outfile_path)

        # Save output
        nmap_save outfile if datastore['NMAP_SAVE']
      else
        print_error 'Nmap Warning: Output file is empty, no useful results can be processed.'
      end
    ensure
      outfile.close
      outfile.unlink
    end
  end

  def nmap_get_path
    ret = Rex::FileUtils.find_full_path("nmap") || Rex::FileUtils.find_full_path("nmap.exe")
    if ret
      fullpath = ::File.expand_path(ret)
      if fullpath =~ /\s/ # Thanks, "Program Files"
        return "\"#{fullpath}\""
      else
        return fullpath
      end
    end
  end

  def nmap_run(cmd)
    begin
      nmap_pipe = ::Open3::popen3(cmd)
      nmap_pid = nmap_pipe.last.pid
      print_status "Nmap: Starting Nmap with pid #{nmap_pid}"
      temp_nmap_threads = []
      temp_nmap_threads << framework.threads.spawn('nmap-stdout', false, nmap_pipe[1]) do |np_1|
        np_1.each_line do |nmap_out|
          next if nmap_out.strip.empty?
          if not datastore['NMAP_VERBOSE'] and nmap_out =~ /^Discovered open port /
            port, proto, ip = nmap_out.match(/^Discovered open port (\d+)\/(\w{3}) on (.+)$/).captures
            print_status("#{ip}:#{port} - #{proto.upcase} OPEN")
          end
          print_status "Nmap: #{nmap_out.strip}" if datastore['NMAP_VERBOSE']
        end
      end

      temp_nmap_threads << framework.threads.spawn('nmap-stderr', false, nmap_pipe[2]) do |np_2|
        np_2.each_line do |nmap_err|
          next if nmap_err.strip.empty?
          print_status  "Nmap: '#{nmap_err.strip}'"
        end
      end

      temp_nmap_threads.map {|t| t.join rescue nil}
      nmap_pipe.each {|p| p.close rescue nil}
    rescue ::IOError
    end
  end

  def nmap_save(outfile)
    print_status 'Nmap: saving nmap log file'
    nmap_data = outfile.read(outfile.stat.size)
    saved_path = store_local('nmap.scan.xml', 'text/xml', nmap_data, "nmap_#{(Time.now.to_f * 1000).to_i}.xml")
    print_status "Saved NMAP XML results to #{saved_path}"
  end

end