##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/http'
require 'yaml'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'   		  => 'HTTP Vuln Scanner',
      'Description'	=> %q{
        This module is a port of the Nmap 'http-enum' script. It enumerates directories used by popular web applications and servers.
      },
      'Author' 		  => 'Sion Dafydd <sion.dafydd[at]gmail.com>',
      'License'		  => BSD_LICENSE
    )

    register_options(
      [
        OptString.new('PATH', [ true, 'Test base path', '/']),
        OptBool.new('DISPLAYALL', [ true, 'Display all status codes that may indicate a valid page, not just 200 and 401', false ]),
        OptPath.new('FINGERPRINTS',[ true, 'Path to yaml file containing fingerprints', File.join(Msf::Config.config_directory, 'data', 'http_fingerprints.yml') ])
      ]
    )

    register_advanced_options(
      [
        OptInt.new('ErrorCode', [ true,  'The expected HTTP status code for non existant files', 404 ]),
        OptPath.new('HTTP404Sigs', [ false, 'Path of 404 signatures to use', File.join(Msf::Config.data_directory, 'wmap', 'wmap_404s.txt') ]),
        OptBool.new('ForceCode', [ false, 'Force detection using HTTP status code', false ]),
        OptInt.new('TestThreads', [ true, 'The number of test threads', 25 ])
      ]
    )
  end

  def run_host(ip)
    usecode = datastore['ForceCode']

    # Remove trailing slash if it exists
    base_path = normalize_uri(datastore['PATH'])
    if base_path[-1,1] == '/'
      base_path.chop!
    end

    displayall = datastore['DISPLAYALL']

    num_threads = datastore['TestThreads'].to_i
    num_threads = 1 if num_threads == 0

    queue = []

    fingerprints = YAML.load_file(datastore['FINGERPRINTS'])
    fingerprints.each do |fingerprint|
      queue << fingerprint
    end

    #
    # Detect error code
    #
    ecode = datastore['ErrorCode'].to_i
    begin
      conn = true
      tries ||= 3

      random_file = Rex::Text.rand_text_alpha(5).chomp

      response = send_request_cgi({
                                 'uri'  	=> base_path+random_file,
                                 'method' => 'GET',
                                 'ctype'	=> 'text/html'
                             }, 20)

      return unless response

      tcode = response.code.to_i

      # Look for a string we can signature on as well
      if(tcode >= 200 and tcode <= 299)
        emesg = nil
        File.open(datastore['HTTP404Sigs'], 'rb').each do |str|
          if(response.body.index(str))
            emesg = str
            break
          end
        end

        if not emesg
          print_status('Using first 256 bytes of the response as 404 string')
          emesg = response.body[0,256]
        else
          print_status("Using custom 404 string of '#{emesg}'")
        end
      else
        ecode = tcode
        print_status("Using code '#{ecode}' as not found.")
      end

    rescue ::Rex::ConnectionTimeout
      retry unless (tries -= 1).zero?
      conn = false
      print_error('Unable to connect, connection timed out') if tries.zero?
    rescue ::Rex::ConnectionRefused
      conn = false
      print_error('Unable to connect, connection refused by server')
    rescue ::Rex::HostUnreachable
      conn = false
      print_error('Unable to connect, host unreachable')
    end

    return unless conn

    #
    # Start testing
    #
    while(not queue.empty?)
      test_threads = []
      1.upto(num_threads) do
        test_threads << framework.threads.spawn("Module(#{self.refname})-#{ip}", false, queue.shift) do |fingerprint|
          Thread.current.kill unless fingerprint

          category = fingerprint['category']
          probes = fingerprint['probes']
          matches = fingerprint['matches']

          # loop through probes
          probes.each do |probe|
            output = nil

            if probe.key?('method')
              method = probe['method']
            else
              method = 'GET'
            end

            begin
              conn = true
              tries ||= 3

              # send probe
              response = send_request_cgi({
                                         'uri'  	=> base_path + probe['path'],
                                         'method' => method,
                                         'ctype'	=> 'text/plain'
                                     }, 20)

            rescue ::Rex::ConnectionTimeout
              retry unless (tries -= 1).zero?
              conn = false
              print_error('Unable to connect, connection timed out') if tries.zero?
            rescue ::Rex::ConnectionRefused
              conn = false
              print_error('Unable to connect, connection refused by server')
            rescue ::Rex::HostUnreachable
              conn = false
              print_error('Unable to connect, host unreachable')
            end

            # Check if connection was successful and response was received, move on to next probe if not
            next unless conn and response

            # check if 404 or error code
            if((response.code.to_i == ecode) or (emesg and response.body.index(emesg)))
              vprint_status("#{wmap_base_url}#{base_path}#{probe['path']} [#{response.code.to_i}]")
              # move on to next probe
              next
            else
              if response.code.to_i == 400
                print_error("#{wmap_base_url}#{base_path}#{probe['path']} [#{response.code.to_i}]")
                # move on to next probe
                next
              elsif not displayall
                unless response.code.to_i == 200 or response.code.to_i == 401
                  vprint_status("#{wmap_base_url}#{base_path}#{probe['path']} [#{response.code.to_i}]")
                  # move on to next probe
                  next
                end
              end
            end

            # loop through matches
            matches.each do |match|
              output = nil

              # Change blank 'match' strings to '.*' so they match everything
              if match['match'].nil? or match['match'].empty?
                match['match'] = '(.*)'
              end

              success, captures = response_contains(response, match['match'])
              if success
                output = match['output']
                captures.length.times do |count|
                  output.gsub!('\\' + (count.to_i + 1).to_s, captures[count])
                end
              end

              if match.key?('dontmatch')
                success, captures = response_contains(response, match['dontmatch'])
                if success
                  output = nil
                end
              end

              break if output
            end

            if not output.nil?
              print_good("#{wmap_base_url}#{base_path}#{probe['path']} [#{response.code.to_i}] : #{output}")

              report_note(
                  :host    => ip,
                  :port    => rport,
                  :proto   => 'tcp',
                  :sname   => (ssl ? 'https' : 'http'),
                  :type    => 'web_enum',
                  :data    => "#{wmap_base_url}#{base_path}#{probe['path']} [#{response.code}] : #{output}"
              )

              report_web_vuln(
                  :host	=> ip,
                  :port	=> rport,
                  :vhost  => vhost,
                  :ssl    => ssl,
                  :path	=> "#{base_path}#{probe['path']}",
                  :method => method,
                  :pname  => '',
                  :proof  => "[#{response.code}] : #{output}",
                  :risk   => 0,
                  :confidence   => 100,
                  :category     => 'web_enum',
                  :description  => 'Interesting resource enumerated',
                  :name   => 'web_enum'
              )

              break
            else
              vprint_status("#{wmap_base_url}#{base_path}#{probe['path']} [#{response.code.to_i}]")
            end
          end
        end
      end

      test_threads.map{|t| t.join }
    end
  end

  def response_contains(response, pattern, case_sensitive=false)
    captures = Array.new

    # If they're searching for the empty string or nil, it's true
    if pattern.nil? or pattern.empty?
      return true, captures
    end

    if case_sensitive
      regex = Regexp.new(pattern, Regexp::MULTILINE)
    else
      regex = Regexp.new(pattern, Regexp::MULTILINE || Regexp::IGNORECASE)
    end

    # Check the status line (eg, 'HTTP/1.1 200 OK')
    if response.cmd_string.match(regex)
      captures = response.body.match(regex).captures
      return true, captures
    end

    # Check the headers
    if response.headers.to_s.match(regex)
      captures = response.body.match(regex).captures
      return true, captures
    end

    # Check the body
    if response.body.match(regex)
      captures = response.body.match(regex).captures
      return true, captures
    end

    return false, captures
  end
end
