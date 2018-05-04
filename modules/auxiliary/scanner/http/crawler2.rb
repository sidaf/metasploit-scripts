##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Web Site Crawler',
      'Description' => 'Crawl a web site and store information about what was found',
      'Author'      => [ 'hdm', 'tasos', 'Sion Dafydd <sion.dafydd[at]gmail.com>' ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
          Opt::RHOST,
          Opt::RPORT(80),
          OptString.new('VHOST', [ false, "HTTP server virtual host" ]),
          OptBool.new('SSL', [ false, 'Negotiate SSL/TLS for outgoing connections', false]),
          OptString.new('PATH', [ true,  "The starting path to crawl", '/']),
          OptInt.new('MAX_PAGES', [ true, 'The maximum number of pages to crawl per URL', 100]),
          #OptInt.new('MAX_MINUTES', [ true, 'The maximum number of minutes to spend on each URL', 5]),
          OptBool.new('ENABLE_COOKIES', [ true, 'Enable cookie persistence during crawl' ])
      ]
    )

    register_advanced_options(
      [
          OptString.new('UserAgent', [ false, 'The User-Agent header to use for all requests', Rex::Proto::Http::Client::DefaultUserAgent ]),
          OptString.new('ExcludePathPatterns', [ false, 'Newline-separated list of path patterns to ignore (\'*\' is a wildcard)']),
          #OptInt.new('RetryLimit', [ false, 'The maximum number of attempts for a single request', 3]),
          OptInt.new('MaxThreads', [ true, "The maximum number of concurrent requests", 10])
      ]
    )
  end

  def run
    #
    # Assign variables
    #
    num_threads = datastore['MaxThreads'].to_i
    num_threads = 1 if num_threads == 0
    max_pages = datastore['MAX_PAGES'].to_i
    cookies_enabled = datastore['ENABLE_COOKIES']
    queue = Array.new
    visited = Hash.new

    #
    # Start testing
    #
    path, query = normalize_uri(datastore['PATH']).split('?', 2)
    query ||= ""

    t = WebTarget.new

    t.merge!(
      {
        :vhost    => vhost,
        :host     => rhost,
        :port     => rport,
        :ssl      => ssl,
        :path     => path,
        :query    => query,
        :info     => ""
      }
    )

    t[:site] = report_web_site(:wait => true, :host => t[:host], :port => t[:port], :vhost => t[:vhost], :ssl => t[:ssl])

    print_status("Crawling #{t.to_url}...")

    Typhoeus::Config.user_agent = datastore['UserAgent']
    hydra = Typhoeus::Hydra.new(:max_concurrency => num_threads)
    resolve = Ethon::Curl.slist_append(nil, "#{vhost}:#{rport}:#{rhost}")

    # Set default request options
    options = {
        resolve: resolve,
        method: 'GET',
        followlocation: false,
        connecttimeout: 20,
        ssl_verifyhost: 0,
        ssl_verifypeer: false
    }

    # Configure cookie jar
    if cookies_enabled
      cookie_file = Tempfile.new 'cookies'
      options[:cookiefile] = cookie_file
      options[:cookiejar] = cookie_file
    end

    queue << t.to_url

    # crawl target
    count = 0

    while not queue.empty?
      queue.size.times do
        url = queue.shift

        if !max_pages.nil? && visited.size >= max_pages
          print_status("Crawling done! Visited MAX_PAGES (#{visited.size}/#{max_pages})")
          queue = Array.new
          break
        end

        visited[url] = 1

        request = Typhoeus::Request.new(url, options)

        request.on_complete do |response|
          if response.timed_out?
            print_error("#{url}, connection timed out (#{wmap_target_host})")
            return
          end

          if response.code.zero?
            print_error("#{url}, could not get a http response (#{wmap_target_host})")
            return
          end

          count += 1

          # Extract any interesting data from the page
          process_page(t, url, response, count)

          # Extract URLs
          urls = extract_urls(t, url, response)

          # Add URLs to queue, unless already visited
          urls.each do |new_url|
            next if visited.key? new_url
            queue << new_url
          end
        end

        hydra.queue request
      end

      hydra.run
    end
  end

  def extract_urls(t, url, response)
    urls = Array.new

    doc = Nokogiri::HTML(response.body) if response.body rescue nil
    if doc
      # Anchors
      urls += doc.search( '//a[@href]' ).map { |a| a['href'] }

      # Areas
      urls += doc.search( '//area[@href]' ).map { |a| a['href'] }

      # Comments
      urls += doc.xpath( '//comment()' ).map do |comment|
        comment.text.scan( /(^|\s)(\/[\/a-zA-Z0-9%._-]+)/ )
      end.flatten.select { |s| s.start_with? '/' }

      # Data URL
      urls += doc.search( '//a[@data-url]' ).map { |a| a['data-url'] }

      # Forms
      urls += doc.search( '//form[@action]' ).map { |a| a['action'] }

      # Frames
      urls += doc.css( 'frame', 'iframe' ).map { |a| a.attributes['src'].content rescue next }

      # Generic
      begin
        urls += URI.extract( html, %w(http https) ).map do |u|
          if !includes_quotes?(u)
            u
          else
            if html.include?("'#{u}")
              u.split( '\'' ).first
            elsif html.include?("\"#{u}")
              u.split('"').first
            else
              u
            end
          end
        end
      rescue
      end

      # Links
      urls += doc.search( '//link[@href]' ).map { |a| a['href'] }

      # Scripts
      urls += doc.search( '//script[@src]' ).map { |a| a['src'] } |
          doc.xpath( '//script' ).map(&:text).join.
              scan( /[\/a-zA-Z0-9%._-]+/ ).select do |s|
                # String looks like a path, but don't get fooled by comments.
                s.include?('.') && s.include?('/')  && !s.include?('*') && !s.start_with?('//') &&
                # Require absolute paths, otherwise we may get caught in
                # a loop, this context isn't the most reliable for extracting
                # real paths.
                s.start_with?('/')
              end

      # Meta-refresh
      urls += doc.search( "//meta[translate(@http-equiv,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz') = 'refresh']" ).map do |url|
        begin
          _, url = url['content'].split(';', 2)
          next unless url
          unquote(url.split('=', 2).last)
        rescue
          next
        end
      end
    end

    # Capture location header in 30X redirects
    if response.code == 301 or response.code == 302
      if response.headers and response.headers["location"]
        urls << response.headers["location"].to_s
      end
    end

    # Make URLs absolute
    absolute_urls = Array.new
    urls.each do |u|
      absolute_urls << to_absolute(u, url).to_s rescue next
    end

    # Filter URLs based on regex, domain, schema, and port
    valid_urls = Array.new
    absolute_urls.each do |u|
      next if u =~ get_link_filter
      next unless URI(url).host == URI(u).host
      next unless URI(url).scheme == URI(u).scheme
      next unless URI(url).port == URI(u).port
      # TODO ignore ajax links
      # If we get to here, url must be valid
      valid_urls << u
    end

    valid_urls
  end

  def unquote(str)
    [ '\'', '"' ].each do |q|
      return str[1...-1] if str.start_with?( q ) && str.end_with?(q)
    end
    str
  end

  # Data we will report:
  # - The path of any URL found by the crawler (web.uri, :path => page.path)
  # - The occurrence of any form (web.form :path, :type (get|post|path_info), :params)
  def process_page(t, url, response, count)
    msg = "[#{"%.3d" % count}/#{"%.3d" % datastore['MAX_PAGES']}]  #{response.code || "ERR"} - #{t[:host]} - #{url}"
    case response.code
      when 301,302
        if response.headers and response.headers["location"]
          print_status(msg + " -> " + response.headers["location"].to_s)
        else
          print_status(msg)
        end
      when 500...599
        print_good(msg)
      when 401,403
        print_good(msg)
      when 200
        print_status(msg)
      when 404
        print_error(msg)
      else
        print_error(msg)
    end

    #
    # Process the web page
    #
    uri = URI(url)
    info = {
        :web_site => t[:site],
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

    # Only process interesting response codes
    return unless [302, 301, 200, 500, 401, 403, 404].include?(response.code)

    # Skip certain types of forms right off the bat

    # Apache multiview directories
    return if uri.query =~ /^C=[A-Z];O=/ # Apache

    forms = []
    form_template = { :web_site => t[:site] }

    if form = form_from_url(t[:site], url)
      forms << form
    end

    doc = Nokogiri::HTML(response.body) if response.body rescue nil
    if doc
      doc.css("form").each do |f|
        target = uri

        if f['action'] and not f['action'].strip.empty?
          action = f['action']

          # Prepend relative URLs with the current directory
          if action[0,1] != "/" and action !~ /\:\/\//
            # Extract the base href first
            base = uri.path.gsub(/(.*\/)[^\/]+$/, "\\1")
            doc.css("base").each do |bref|
              if bref['href']
                base = bref['href']
              end
            end
            action = (base + "/").sub(/\/\/$/, '/') + action
          end

          target = to_absolute(URI(action), uri) rescue next

          target = URI(target)
          unless target.host == uri.host
            # Replace 127.0.0.1 and non-qualified hostnames with our response.host
            # ex: http://localhost/url OR http://www01/url
            if (target.host.index(".").nil? or target.host == "127.0.0.1")
              target.host = uri.host
            else
              next
            end
          end
        end

        # skip this form if it matches exclusion criteria
        unless target.to_s =~ get_link_filter   # TODO will need to filter more than this
          form = {}.merge!(form_template)
          form[:method] = (f['method'] || 'GET').upcase
          form[:query]  = target.query.to_s if form[:method] != "GET"
          form[:path]   = target.path
          form[:params] = []
          f.css('input', 'textarea').each do |inp|
            form[:params] << [inp['name'].to_s, inp['value'] || inp.content || '', { :type => inp['type'].to_s }]
          end

          f.css( 'select' ).each do |s|
            value = nil

            # iterate over each option to find the default value (if there is a selected one)
            s.children.each do |opt|
              ov = opt['value'] || opt.content
              value = ov if opt['selected']
            end

            # set the first one as the default value if we don't already have one
            value ||= s.children.first['value'] || s.children.first.content rescue ''

            form[:params] << [ s['name'].to_s, value.to_s, [ :type => 'select'] ]
          end

          forms << form
        end
      end
    end

    # Report each of the discovered forms
    forms.each do |form|
      next unless form[:method]
      print_status((" " * 24) + "FORM: #{form[:method]} #{form[:path]}")
      report_web_form(form)
    end
  end

  def form_from_url(website, url)
    url = URI( url.to_s ) if !url.is_a?( URI )

    begin
      # Scrub out the jsessionid appends
      url.path = url.path.sub(/;jsessionid=[a-zA-Z0-9]+/, '')
    rescue URI::Error
    end

    # Continue processing forms
    form_template = { :web_site => website }
    form  = {}.merge(form_template)

    # This page has a query parameter we can test with GET parameters
    # ex: /test.php?a=b&c=d
    if url.query and not url.query.empty?
      form[:method] = 'GET'
      form[:path]   = url.path
      vars = url.query.split('&').map{|x| x.split("=", 2) }
      form[:params] = vars
    end

    # This is a REST-ish application with numeric parameters
    # ex: /customers/343
    if not form[:path] and url.path.to_s =~ /(.*)\/(\d+)$/
      path_base = $1
      path_info = $2
      form[:method] = 'PATH'
      form[:path]   = path_base
      form[:params] = [['PATH', path_info]]
      form[:query]  = url.query.to_s
    end

    # This is an application that uses PATH_INFO for parameters:
    # ex:  /index.php/Main_Page/Article01
    if not form[:path] and url.path.to_s =~ /(.*\/[a-z0-9A-Z]{3,256}\.[a-z0-9A-Z]{2,8})(\/.*)/
      path_base = $1
      path_info = $2
      form[:method] = 'PATH'
      form[:path]   = path_base
      form[:params] = [['PATH', path_info]]
      form[:query]  = url.query.to_s
    end

    form[:method] ? form : nil
  end

  def get_link_filter
    return /\.(js|png|jpe?g|bmp|gif|swf|jar|zip|gz|bz2|rar|xz|7z|iso|pdf|docx?|pptx?)$/i if datastore['ExcludePathPatterns'].to_s.empty?

    patterns = opt_patterns_to_regexps( datastore['ExcludePathPatterns'].to_s )
    patterns = patterns.map { |r| "(#{r.source})" }

    Regexp.new( [["(#{super.source})"] | patterns].join( '|' ) )
  end

  def opt_patterns_to_regexps(patterns)
    magic_wildcard_replacement = Rex::Text.rand_text_alphanumeric( 10 )
    patterns.to_s.split(/[\r\n]+/).map do |p|
      Regexp.new '^' + Regexp.escape(p.gsub('*', magic_wildcard_replacement)).gsub(magic_wildcard_replacement, '.*') + '$'
    end
  end

  # Converts relative URL *link* into an absolute URL based on the location of the page
  def to_absolute(link, url)
    return nil if link.nil?
    url = URI(url.to_s) unless url.is_a?(URI)

    # remove anchor
    link = URI.encode(link.to_s.gsub(/#[a-zA-Z0-9_-]*$/,''))

    relative = URI(link)
    absolute = url.merge(relative)

    absolute.path = '/' if absolute.path.nil? or absolute.path.empty?

    return absolute
  end

  # Returns a modified version of the URI that:
  # 1. Always has a starting slash
  # 2. Removes all the double slashes
  def normalize_uri(*strs)
    new_str = strs * "/"

    new_str = new_str.gsub!("//", "/") while new_str.index("//")

    # Makes sure there's a starting slash
    unless new_str[0,1] == '/'
      new_str = '/' + new_str
    end

    new_str
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

  # A target object for tracking URLs
  class WebTarget < ::Hash
    def to_url
      proto = self[:ssl] ? "https" : "http"
      host = self[:vhost] ? self[:vhost] : self[:host]
      if Rex::Socket.is_ipv6?(host)
        host = "[#{host}]"
      end
      "#{proto}://#{host}:#{self[:port]}#{self[:path]}"
    end
  end
end
