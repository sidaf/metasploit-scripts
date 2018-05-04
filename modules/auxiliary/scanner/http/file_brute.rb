##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'thread'
require_relative '../../../../lib/typhoeus'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::WmapScanDir
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'   		  => 'HTTP File Brute Forcer',
      'Description'	=> %q{
        This module identifies the existence of interesting files in a given directory path.
      },
      'Author' 		  => [ 'et', 'Sion Dafydd <sion.dafydd[at]gmail.com>' ],
      'License'		  => BSD_LICENSE)
    )

    register_options(
      [
          Opt::RHOST,
          Opt::RPORT(80),
          OptString.new('VHOST', [ false, "HTTP server virtual host" ]),
          OptBool.new('SSL', [ false, 'Negotiate SSL/TLS for outgoing connections', false]),
          OptString.new('PATH', [ true,  "Base path to identify files", '/']),
          OptBool.new('APPENDEXT', [ false, "Append file extensions", true]),
          OptString.new('EXT', [ false, "Append additional file extension", '']),
          OptPath.new('DICTIONARY', [ false, "Path of word dictionary to use", File.join(Msf::Config.data_directory, "wmap", "wmap_files.txt") ])
      ]
    )

    register_advanced_options(
      [
          OptString.new('UserAgent', [false, 'The User-Agent header to use for all requests', Rex::Proto::Http::Client::DefaultUserAgent ]),
          OptInt.new('ErrorCode', [ true,  "The expected HTTP status code for non existant files"]),
          OptPath.new('HTTP404Sigs', [ false, "Path of 404 signatures to use", File.join(Msf::Config.data_directory, "wmap", "wmap_404s.txt") ]),
          OptInt.new('MaxThreads', [ true, "The maximum number of concurrent requests", 10])
      ]
    )

    deregister_options('RHOSTS')
  end

  def run
    #
    # Assign variables
    #
    num_threads = datastore['MaxThreads'].to_i
    num_threads = 1 if num_threads == 0

    extensions = [
        '.null',
        '.backup',
        '.bak',
        '.c',
        '.cfg',
        '.class',
        '.copy',
        '.conf',
        '.exe',
        '.html',
        '.htm',
        '.ini',
        '.log',
        '.old',
        '.orig',
        '.php',
        '.tar',
        '.tar.gz',
        '.tgz',
        '.tmp',
        '.temp',
        '.txt',
        '.zip',
        '~',
        '',
        '.asp',
        '.aspx'
    ]
    extensions << datastore['EXT'] unless datastore['EXT'].empty?

    if not datastore['APPENDEXT']
      extensions = ['']
    end

    #
    # Generate wordlist
    #
    queue = Queue.new
    extensions.each do |ext|
      File.open(datastore['DICTIONARY'], 'rb').each_line do |testf|
        file = testf.strip                      # remove newline characters
        file = file[1..-1] if file[0,1] == '/' # remove leading slash if it exists
        queue.push "#{file}#{ext}"
      end
    end

    #
    # Detect error code
    #
    ecode, emesg = detect_error_code
    return if ecode.nil?

    #
    # Start testing
    #
    Typhoeus::Config.user_agent = datastore['UserAgent']
    hydra = Typhoeus::Hydra.new(:max_concurrency => num_threads)
    resolve = Ethon::Curl.slist_append(nil, "#{vhost}:#{rport}:#{rhost}")

    begin
      while testfile = queue.pop(true)
        testurl = "#{(ssl ? 'https' : 'http')}://#{vhost}:#{rport}#{base_path}#{testfile}"

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

        request.on_complete do |response|
          if response.timed_out?
            print_error("TMO - #{rhost} - #{response.request.url}")
            # move on to next probe
            next
          end

          if response.code.zero?
            print_error("ERR - #{rhost} - #{response.request.url}")
            # move on to next probe
            next
          end

          msg = "#{response.code || "ERR"} - #{rhost} - #{response.request.url}"

          # check if 404 or error code
          if (response.code == ecode) || (emesg && response.body.index(emesg))
            vprint_status(msg)
          else
            report_web_vuln(
                :host	       => rhost,
                :port	       => rport,
                :vhost       => vhost,
                :ssl         => ssl,
                :path	       => "#{base_path}#{testfile}",
                :method      => 'GET',
                :pname       => '',
                :proof       => "Res code: #{response.code.to_s}",
                :risk        => 0,
                :confidence  => 100,
                :category    => 'file',
                :description => 'File found.',
                :name        => 'file'
            )

            if response.code.to_i == 301 or response.code.to_i == 302
              if response.headers and response.headers["location"]
                print_status(msg + " -> " + response.headers["location"].to_s)
              else
                print_status(msg)
              end
            else
              print_good(msg)
            end

            if response.code.to_i == 401
              print_good((" " * 24) + "WWW-Authenticate: #{response.headers['WWW-Authenticate']}")

              report_note(
                  :host	  => rhost,
                  :port	  => rport,
                  :proto  => 'tcp',
                  :sname	=> (ssl ? 'https' : 'http'),
                  :type	  => 'WWW_AUTHENTICATE',
                  :data	  => "#{wmap_base_url}#{base_path}#{testdir} Auth: #{response.headers['WWW-Authenticate']}",
                  :update => :unique_data
              )
            end

            # Report a valid website and webpage to the database
            report(response)
          end
        end

        hydra.queue request
      end
    rescue ThreadError
    rescue => e
      puts e.backtrace
      raise
    end

    hydra.run
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
    # Add trailing slash if it does not exist
    base_path = normalize_uri(datastore['PATH'])
    if base_path[-1,1] != '/'
      base_path += '/'
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
      testurl = "#{baseurl}#{random_file}"
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
        return nil, nil
      end

      if response.code.zero?
        print_error("ERR - #{rhost} - #{baseurl}")
        return nil, nil
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
    else
      print_status("Using assigned code '#{ecode}' as not found for #{baseurl} (#{rhost})")
    end

    return ecode, emesg
  end
end
