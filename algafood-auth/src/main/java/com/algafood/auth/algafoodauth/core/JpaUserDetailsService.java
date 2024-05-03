package com.algafood.auth.algafoodauth.core;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.algafood.auth.algafoodauth.domain.Usuario;
import com.algafood.auth.algafoodauth.domain.UsuarioRepository;

@Service
public class JpaUserDetailsService implements UserDetailsService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        Usuario usuario = usuarioRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrato."));
        usuario.setSenha(encoder.encode(usuario.getSenha()));

        return new AuthUser(usuario, getAuthorities(usuario));
    }

    public Collection<GrantedAuthority> getAuthorities(Usuario user) {

        return user.getGrupos().stream()
                .flatMap(grupo -> grupo.getPermissoes().stream())
                .map(permissao -> new SimpleGrantedAuthority(permissao.getNome().toUpperCase()))
                .collect(Collectors.toSet());
    }
}
