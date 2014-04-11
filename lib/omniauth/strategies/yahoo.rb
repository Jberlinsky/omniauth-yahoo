require 'omniauth-oauth'
require 'multi_json'

module OmniAuth
  module Strategies

    # An omniauth 1.0 strategy for yahoo authentication
    class Yahoo < OmniAuth::Strategies::OAuth

      option :name, 'yahoo'

      option :client_options, {
        :access_token_path  => '/oauth/v2/get_token',
        :authorize_path     => '/oauth/v2/request_auth',
        :request_token_path => '/oauth/v2/get_request_token',
        :site               => 'https://api.login.yahoo.com',
        :ssl                => '/etc/ssl/certs/ca-certificates.crt'
      }

      uid {
        access_token.params['xoauth_yahoo_guid']
      }

      info do
        primary_email = nil
        if user_info['emails']
          email_info    = user_info['emails'].find{|e| e['primary']} || user_info['emails'].first
          primary_email = email_info['handle']
        end
        {
          :nickname    => user_info['nickname'],
          :name        => user_info['givenName'] || user_info['nickname'],
          :image       => user_info['image']['imageUrl'],
          :description => user_info['message'],
          :email       => primary_email,
          :urls        => {
            'Profile' => user_info['profileUrl'],
          }
        }
      end

      extra do
        hash = {}
        hash[:raw_info] = raw_info unless skip_info?
        hash
      end

      # Return info gathered from the v1/user/:id/profile API call

      def raw_info
        yql = "select * from social.profile where guid='#{uid}'"
        request = "https://query.yahooapis.com/v1/yql?q=#{encode_uri_component(yql)}&format=json"
        @raw_info ||= MultiJson.decode(access_token.get(request).body)
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

      # Provide the "Profile" portion of the raw_info

      def user_info
        @user_info ||= raw_info.nil? ? {} : raw_info['query']['results']["profile"]
      end

      def gsub(input, replace)
        search = Regexp.new(replace.keys.map{|x| "(?:#{Regexp.quote(x)})"}.join('|'))
        input.gsub(search, replace)
      end

      def encode_uri_component(val)
        # encodeURIComponent(symbols) === "%20   ! %22 %23 %24 %25 %26   '   (   )   * %2B %2C - . %2F %3A %3B %3C %3D %3E %3F %40 %5B %5C %5D %5E _ %60 %7B %7C %7D   ~"
        # CGI.escape(symbols)         === "  + %21 %22 %23 %24 %25 %26 %27 %28 %29 %2A %2B %2C - . %2F %3A %3B %3C %3D %3E %3F %40 %5B %5C %5D %5E _ %60 %7B %7C %7D %7E"
        gsub(CGI.escape(val.to_s),
             '+'   => '%20',  '%21' => '!',  '%27' => "'",  '%28' => '(',  '%29' => ')',  '%2A' => '*',
             '%7E' => '~'
        )
      end
    end
  end
end
