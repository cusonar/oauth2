package com.cusonar.oauth;

import javax.sql.DataSource;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.authserver.AuthorizationServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.authserver.OAuth2AuthorizationServerConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@SpringBootApplication
@EnableAuthorizationServer
public class OauthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(OauthServerApplication.class, args);
	}
}

@Configuration
class OAuth2Configuration {
	
	@Value("${keystore.password}") public String password;

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
    		System.out.println(this.password);
    		KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), password.toCharArray());
    		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
    		jwtAccessTokenConverter.setKeyPair(keyStoreKeyFactory.getKeyPair("jwt"));
        return jwtAccessTokenConverter;
    }
    
    @Bean
    @Primary
    public JdbcClientDetailsService jdbcClientDetailsService(DataSource dataSource) {
        return new JdbcClientDetailsService(dataSource);
    }
}

@Configuration
class JwtOAuth2AuthorizationServerConfiguration extends OAuth2AuthorizationServerConfiguration {

    private final JwtAccessTokenConverter jwtAccessTokenConverter;
    private final ClientDetailsService clientDetailsService;

    public JwtOAuth2AuthorizationServerConfiguration(BaseClientDetails details,
			AuthenticationManager authenticationManager, ObjectProvider<TokenStore> tokenStore,
			ObjectProvider<AccessTokenConverter> tokenConverter, AuthorizationServerProperties properties,
			ClientDetailsService clientDetailsService) {
		super(details, authenticationManager, tokenStore, tokenConverter, properties);
		this.jwtAccessTokenConverter = (JwtAccessTokenConverter) tokenConverter.getObject();
		this.clientDetailsService = clientDetailsService;
	}

	@Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints)
            throws Exception {
        super.configure(endpoints);
        endpoints.accessTokenConverter(jwtAccessTokenConverter);
    }

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.withClientDetails(clientDetailsService);
	}	
}
