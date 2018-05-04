##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require_relative '../../../../lib/typhoeus'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report


  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP Virtual Host Brute Force Scanner',
      'Description'	=> %q{
          This module tries to identify unique virtual hosts served by the target web server.
      },
      'Author' 		  => [ 'et [at] cyberspace.org', 'Sion Dafydd <sion.dafydd[at]gmail.com>' ],
      'License'		  => BSD_LICENSE)
    )

    register_options(
      [
          OptBool.new('SSL', [ false, 'Negotiate SSL/TLS for outgoing connections', false]),
          OptString.new('PATH', [ true,  "The PATH to use while testing", '/']),
          OptPath.new('FQDN_LIST', [true, "Path to text file with fully qualified domains"])
      ]
    )
  end

  def run_host(ip)
    #
    # Assign variables
    #
    ssl = datastore['SSL']

    base_path = normalize_uri(datastore['PATH'])

    valstr = IO.readlines(datastore['FQDN_LIST']).map do |e|
      e.chomp
    end

    resparr = []

    #
    # Detect error code
    #
    2.times do |n|

      randvhost = Rex::Text.rand_text_alpha(5) + "." + Rex::Text.rand_text_alpha(5) + ".com"

      url = "#{(ssl ? 'https' : 'http')}://#{randvhost}:#{rport}#{base_path}"
      resolve = Ethon::Curl.slist_append(nil, "#{randvhost}:#{rport}:#{rhost}")

      Typhoeus::Config.user_agent = datastore['UserAgent']

      trequest = Typhoeus::Request.new(
          url,
          resolve: resolve,
          method: 'GET',
          followlocation: false,
          connecttimeout: 20,
          ssl_verifyhost: 0,
          ssl_verifypeer: false
      )

      #print_status("[#{ip}] Sending request with a random domain #{randvhost}")
      tresponse = trequest.run

      if tresponse.timed_out?
        print_error("[#{ip}] Unable to connect to #{url}, connection timed out")
        return
      end

      if tresponse.code.zero?
        print_error("[#{ip}] Unable to connect to #{url}, could not get a http response")
        return
      end

      resparr[n] = tresponse.body
    end

    if resparr[0] != resparr[1]
      print_error("Unable to identify an error response on server #{(ssl ? 'https' : 'http')}://#{rhost}:#{rport}")
      return
    end

    #
    # Start testing
    #
    print_status("Testing server #{(ssl ? 'https' : 'http')}://#{rhost}:#{rport} with #{valstr.length} fully qualified domain names.")

    valstr.each do |thost|

      url = "#{(ssl ? 'https' : 'http')}://#{thost}:#{rport}#{base_path}"
      resolve = Ethon::Curl.slist_append(nil, "#{thost}:#{rport}:#{rhost}")

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
        print_error("[#{ip}] Unable to connect to #{url}, connection timed out")
        next
      end

      if response.code.zero?
        print_error("[#{ip}] Unable to connect to #{url}, could not get a http response")
        next
      end

      if resparr[0] != response.body
        print_good("#{url} (#{rhost})")

        report_note(
            :host	=> ip,
            :proto => 'tcp',
            :sname => (ssl ? 'https' : 'http'),
            :port	=> rport,
            :type	=> 'Virtual host',
            :data	=> thost,
            :update => :unique_data
        )

        report_web_site(
            :wait => true,
            :host => ip,
            :port => rport,
            :vhost => thost,
            :ssl => datastore['SSL']
        )
      else
        vprint_status("#{url} (#{rhost})")
      end
    end
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
end
