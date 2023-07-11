require 'omniauth-oauth2'
require 'base64'

module OmniAuth
  module Strategies
    class Pinterest < OmniAuth::Strategies::OAuth2
      option :client_options, {
        site:          "https://api.pinterest.com/",
        authorize_url: "https://www.pinterest.com/oauth",
        token_url:     "https://api.pinterest.com/v5/oauth/token",
        auth_scheme:   :basic_auth,
      }

      uid { raw_info["id"] }

      info { raw_info }

      def raw_info
        @raw_info ||= access_token.get("/v5/user_account").parsed
      end

      def ssl?
        true
      end

      private

        def callback_url
          options[:redirect_uri] || (full_host + script_name + callback_path)
        end
    end
  end
end
