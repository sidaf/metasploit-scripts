##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'yaml'
require_relative '../../../../lib/typhoeus'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'   		  => 'HTTP Vuln Scanner',
      'Description'	=> %q{
        This module is a port of the Nmap 'http-enum' script. It enumerates files and directories used by popular web applications and servers.
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
          OptString.new('PATH', [ true, 'Test base path', '/']),
          OptBool.new('DISPLAYALL', [ true, 'Display all status codes that may indicate a valid page, not just 200 and 401', false ]),
          OptPath.new('FINGERPRINTS',[ true, 'Path to yaml file containing fingerprints', File.join(Msf::Config.config_directory, 'data', 'http_fingerprints.yml') ])
      ]
    )

    register_advanced_options(
      [
          OptString.new('UserAgent', [false, 'The User-Agent header to use for all requests', Rex::Proto::Http::Client::DefaultUserAgent ]),
          OptInt.new('ErrorCode', [ false,  'The expected HTTP status code for non existant resources' ]),
          OptPath.new('HTTP404Sigs', [ false, 'Path of 404 signatures to use', File.join(Msf::Config.data_directory, 'wmap', 'wmap_404s.txt') ]),
          OptInt.new('MaxThreads', [ true, 'The maximum number of concurrent requests', 10 ])
      ]
    )

    deregister_options('RHOSTS')
  end

  def run
    #
    # Assign variables
    #

    displayall = datastore['DISPLAYALL']

    num_threads = datastore['MaxThreads'].to_i
    num_threads = 1 if num_threads == 0

    #
    # Generate fingerprint list
    #
    queue = Queue.new
    fingerprints = YAML.load_file(datastore['FINGERPRINTS'])
    fingerprints.each do |fingerprint|
      queue.push fingerprint
    end

    #
    # Detect error code
    #
    ecode, emesg = detect_error_code

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
                connecttimeout: 5,
                timeout: 10,
                ssl_verifyhost: 0,
                ssl_verifypeer: false
              )
              response = request.run

              if response.timed_out?
                print_error("TMO - #{rhost} - #{url}")
                # move on to next probe
                next
              end

              if response.code.zero?
                print_error("ERR - #{rhost} - #{url}")
                # move on to next probe
                next
              end

              msg = "#{response.code || "ERR"} - #{rhost} - #{url}"

              # check if 404 or error code
              if (response.code == ecode) || (emesg && response.body.index(emesg))
                vprint_status(msg)
                # move on to next probe
                next
              else
                unless displayall
                  unless response.code == 200 || response.code == 401
                    vprint_status(msg)
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
                  output = nil if success
                end

                break if output
              end

              if output.nil?
                vprint_status(msg)
                next
              else
                report_web_vuln(
                    :host	       => rhost,
                    :port	       => rport,
                    :vhost       => vhost,
                    :ssl         => ssl,
                    :path	       => "#{base_path}#{probe['path']}",
                    :method      => method == 'HEAD' ? 'GET' : method,
                    :pname       => '',
                    :proof       => "Response code: [#{response.code}], Match: #{output}",
                    :risk        => 0,
                    :confidence  => 100,
                    :category    => 'resource',
                    :description => 'Interesting resource enumerated.',
                    :name        => 'resource'
                )

                print_good("#{msg} [#{output}]")

                if response.code.to_i == 401
                  print_good((" " * 24) + "WWW-Authenticate: #{response.headers['WWW-Authenticate']}")

                  report_note(
                      :host	  => rhost,
                      :port	  => rport,
                      :proto  => 'tcp',
                      :sname	=> (ssl ? 'https' : 'http'),
                      :type	  => 'WWW_AUTHENTICATE',
                      :data	  => "#{url} [#{response.code}] Auth: #{response.headers['WWW-Authenticate']} (#{rhost})",
                      :update => :unique_data
                  )
                end

                # Report a valid website and webpage to the database
                report(response)

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

  def base_path
    # Remove trailing slash if it exists
    base_path = normalize_uri(datastore['PATH'])
    if base_path[-1,1] == '/'
      base_path.chop!
    end
    return base_path
  end

  #
  # Returns a modified version of the URI that:
  # 1. Always has a starting slash
  # 2. Removes all the double slashes
  #
  def normalize_uri(*strs)
    new_str = strs * "/"

    new_str = new_str.gsub!("//", "/") while new_str.index("//")

    # Makes sure there's a starting slash
    unless new_str[0,1] == '/'
      new_str = '/' + new_str
    end

    new_str
  end

  def report(response)
    # Report a website to the database
    site = report_web_site(:wait => true, :host => rhost, :port => rport, :vhost => vhost, :ssl => datastore['SSL'])

    uri = URI.parse(response.request.url)
    info = {
        :web_site => site,
        :path     => uri.path,
        :query    => uri.query,
        :code     => response.code,
        :body     => response.body,
        :headers  => response.headers
    }

    if response.headers['content-type']
      info[:ctype] = response.headers['content-type']
    end

    # TODO
    #if !page.cookies.empty?
    #  info[:cookie] = page.cookies
    #end

    if response.headers['authorization']
      info[:auth] = response.headers['authorization']
    end

    if response.headers['location']
      info[:location] = response.headers['location']
    end

    if response.headers['last-modified']
      info[:mtime] = response.headers['last-modified']
    end

    # Report the web page to the database
    report_web_page(info)
  end

  def detect_error_code
    ecode = datastore['ErrorCode'].to_i
    emesg = nil

    if ecode.zero?
      random_file = Rex::Text.rand_text_alpha(8).chomp

      baseurl = "#{(ssl ? 'https' : 'http')}://#{vhost}:#{rport}#{base_path}"
      testurl = "#{baseurl}/#{random_file}"
      resolve = Ethon::Curl.slist_append(nil, "#{vhost}:#{rport}:#{rhost}")

      Typhoeus::Config.user_agent = datastore['UserAgent']

      request = Typhoeus::Request.new(
          testurl,
          resolve: resolve,
          method: 'GET',
          followlocation: false,
          connecttimeout: 5,
          timeout: 10,
          ssl_verifyhost: 0,
          ssl_verifypeer: false
      )
      response = request.run

      if response.timed_out?
        print_error("TMO - #{rhost} - #{baseurl}")
        return
      end

      if response.code.zero?
        print_error("ERR - #{rhost} - #{baseurl}")
        return
      end

      # Look for a string we can signature on as well
      if response.code >= 200 and response.code <= 299
        emesg = nil
        File.open(datastore['HTTP404Sigs'], 'rb').each do |str|
          if response.body.index(str)
            emesg = str
            break
          end
        end

        if not emesg
          print_status("Using first 256 bytes of the response as 404 string for #{baseurl} (#{rhost})")
          emesg = response.body[0,256]
        else
          print_status("Using custom 404 string of '#{emesg}' for #{baseurl} (#{rhost})")
        end
      else
        ecode = response.code.to_i
        print_status("Using code '#{ecode}' as not found for #{baseurl} (#{rhost})")
      end
    end

    return ecode, emesg
  end
end
