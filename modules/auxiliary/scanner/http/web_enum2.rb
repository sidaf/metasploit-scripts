##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/http'
require 'yaml'

require_relative '../../../../lib/typhoeus/lib/typhoeus'
require_relative '../../../../lib/ethon/lib/ethon'

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
        OptInt.new('TestThreads', [ true, 'The number of test threads', 10 ])
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

    queue = Queue.new

    fingerprints = YAML.load_file(datastore['FINGERPRINTS'])
    fingerprints.each do |fingerprint|
      queue.push fingerprint
    end

    #
    # Detect error code
    #
    ecode = datastore['ErrorCode'].to_i
    random_file = Rex::Text.rand_text_alpha(8).chomp

    url = "#{(ssl ? 'https' : 'http')}://#{vhost}:#{rport}#{base_path}/#{random_file}"
    resolve = Ethon::Curl.slist_append(nil, "#{vhost}:#{rport}:#{rhost}")

    Typhoeus::Config.user_agent = datastore['UserAgent']

    request = Typhoeus::Request.new(
        url,
        resolve: resolve,
        method: 'GET',
        followlocation: false,
        connecttimeout: 20,
        ssl_verifyhost: 0,
        ssl_verifypeer: false
    )
    response = request.run

    if response.timed_out?
      print_error('Unable to connect, connection timed out')
      return
    end

    if response.code == 0
      print_error('Unable to connect, could not get a http response')
      return
    end

    # Look for a string we can signature on as well
    if(response.code >= 200 and response.code <= 299)
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
      ecode = response.code.to_i
      print_status("Using code '#{ecode}' as not found.")
    end

    #
    # Start testing
    #
    workers = 1.upto(num_threads).map do
      Thread.new do
        begin
          while fingerprint = queue.pop(true)

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

              url = "#{(ssl ? 'https' : 'http')}://#{vhost}:#{rport}#{base_path}#{probe['path']}"
              resolve = Ethon::Curl.slist_append(nil, "#{vhost}:#{rport}:#{rhost}")

              Typhoeus::Config.user_agent = datastore['UserAgent']

              request = Typhoeus::Request.new(
                  url,
                  resolve: resolve,
                  method: method,
                  followlocation: false,
                  connecttimeout: 20,
                  ssl_verifyhost: 0,
                  ssl_verifypeer: false
              )
              response = request.run

              if response.timed_out?
                print_error("#{wmap_base_url}#{base_path}#{probe['path']}, connection timed out")
                # move on to next probe
                next
              end

              if response.code == 0
                print_error("#{wmap_base_url}#{base_path}#{probe['path']}, could not get a http response")
                # move on to next probe
                next
              end

              # check if 404 or error code
              if((response.code == ecode) or (emesg and response.body.index(emesg)))
                vprint_status("#{wmap_base_url}#{base_path}#{probe['path']} [#{response.code}]")
                # move on to next probe
                next
              else
                unless displayall
                  unless response.code == 200 or response.code == 401
                    vprint_status("#{wmap_base_url}#{base_path}#{probe['path']} [#{response.code}]")
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

              if output.nil?
                vprint_status("#{wmap_base_url}#{base_path}#{probe['path']} [#{response.code}]")
                next
              else
                print_good("#{wmap_base_url}#{base_path}#{probe['path']} [#{response.code}] : #{output}")

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
              end
            end
          end
        rescue ThreadError
        rescue => e
          puts e.backtrace
          raise
        end
      end
    end
    workers.map(&:join)
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

    # Check the headers
    if response.response_headers.match(regex)
      captures = response.response_headers.match(regex).captures
      return true, captures
    end

    # Check the body
    if response.response_body.match(regex)
      captures = response.response_body.match(regex).captures
      return true, captures
    end

    return false, captures
  end
end
