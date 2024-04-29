package com.algafood.auth.algafoodauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    // configuração do password credentials grant no authorizationServer
    // configuração dos cliente permitido a receber o acess token
    // Configuração das aplicação "client" que pode acessar os recurso, usando o
    // acess token
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                .withClient("algafood-web") // identifica o cliente
                .secret(passwordEncoder.encode("web123")) // a senha do cliente
                .authorizedGrantTypes("password") // o fluxo que esse criente pode fazer, precisa desse método
                // ublic void configure(AuthorizationServerEndpointsConfigurer endpoints)
                .scopes("write", "read") // o scope
                .accessTokenValiditySeconds(60 * 60 * 6); // tempo de validação do token
        // .and() // cadastrando mais de um cliente
        // .withClient("app-mobile")
        // .secret(passwordEncoder.encode("web123"))
        // .authorizedGrantTypes("password")
        // .scopes("write", "read");
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()");
        // security.checkTokenAccess("permitAll()");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager);
    }
}