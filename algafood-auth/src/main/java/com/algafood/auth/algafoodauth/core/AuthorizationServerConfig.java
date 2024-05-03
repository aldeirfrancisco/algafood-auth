package com.algafood.auth.algafoodauth.core;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
//import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
//import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    // @Autowired
    // private RedisConnectionFactory connectionFactory;

    // configuração do password credentials grant no authorizationServer
    // configuração dos cliente permitido a receber o acess token
    // Configuração das aplicação "client" que pode acessar os recurso, usando o
    // acess token
    // Configurando o fluxo authorization_code
    // http://localhost:8081/oauth/authorize?response_type=code&client_id=foodAnalystics&state=abc&redirect_uri=http://http://localhost:8082
    // Configurando o fluxo Implicit Grant Type
    // http://localhost:8081/oauth/authorize?response_type=token&client_id=webAdimin&state=abc&redirect_uri=http://aplicacao-cliente

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                .withClient("algafood-web")
                .secret(passwordEncoder.encode("web123"))
                .authorizedGrantTypes("password", "refresh_token")// fluxo password
                .scopes("write", "read")
                .accessTokenValiditySeconds(6 * 60 * 60) // 6 h, padrão 12 h
                .refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60 dias, padrão 30 dias
                .and()
                .withClient("foodanalytics")
                .secret(passwordEncoder.encode("web123"))
                .authorizedGrantTypes("authorization_code") // fluxo authorization_code
                .scopes("write", "read")
                .redirectUris("http://aplicacao-cliente")
                .and()
                .withClient("webAdimin")
                .authorizedGrantTypes("implicit") // fluxo Implicit Grant Type
                .scopes("write", "read")
                .redirectUris("http://aplicacao-cliente")
                .and()
                .withClient("faturamento")
                .secret(passwordEncoder.encode("faturamento123"))
                .authorizedGrantTypes("client_credentials")// fluxo client_credentials
                .scopes("write", "read");

    }

    @Bean // usa o algoritmo HMAC SHA-256 para gera chave simétrica
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setSigningKey("FAFLAFafaaff24rfaou425afa545454afalkj4455443fadj");

        return jwtAccessTokenConverter;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()");
        // security.checkTokenAccess("permitAll()");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .reuseRefreshTokens(false)
                // .tokenStore(redisTokenStore())
                .accessTokenConverter(jwtAccessTokenConverter())
                .approvalStore(approvalStore(endpoints.getTokenStore()))
                .tokenGranter(tokenGranter(endpoints));
    }

    private ApprovalStore approvalStore(TokenStore tokenStore) {
        var approvalStore = new TokenApprovalStore();
        approvalStore.setTokenStore(tokenStore);
        return approvalStore;
    }

    // private TokenStore redisTokenStore() {
    // return new RedisTokenStore(connectionFactory);
    // }

    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
        var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
                endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory());

        var granters = Arrays.asList(
                pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

        return new CompositeTokenGranter(granters);
    }
}