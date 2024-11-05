// Define o pacote onde a classe reside
package com.example.api_user.security;

// Importa o serviço personalizado que carrega os detalhes do usuário.
// Esse serviço é utilizado para buscar as informações do usuário no banco de dados com base no nome de usuário.

import com.example.api_user.service.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Anotação @Configuration:
// - Indica que esta classe faz parte da configuração do Spring. Isso registra a classe como um bean gerenciado pelo Spring.
@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // Dependências injetadas por meio do construtor para manipulação de tokens e carregamento de usuários.
    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService userDetailsService;

    // Construtor que injeta o JwtTokenProvider e o CustomUserDetailsService.
    // - jwtTokenProvider: Responsável por gerar, validar e extrair informações de tokens JWT.
    // - userDetailsService: Serviço que carrega os detalhes do usuário a partir do banco de dados.
    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, CustomUserDetailsService userDetailsService){
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDetailsService = userDetailsService;
    }

    // Sobrescreve o método doFilterInternal para aplicar a lógica do filtro em cada requisição HTTP.
    // - Esse método será chamado automaticamente para cada requisição que chega ao servidor.
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Extrai o valor do cabeçalho "Authorization" da requisição HTTP.
        String authHeader = request.getHeader("Authorization");

        // Se o cabeçalho "Authorization" estiver ausente ou não começar com "Bearer ", o filtro não tenta autenticar.
        // A requisição continua sem autenticação, pois não há um token válido.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Remove a parte "Bearer " do token e mantém apenas o JWT em si.
        String jwt = authHeader.substring(7);

        // Extrai o nome de usuário (username) do token JWT usando o jwtTokenProvider.
        String username = jwtTokenProvider.extractUsername(jwt);
        int userid = jwtTokenProvider.extractUserId(jwt);

        // Inicializa o objeto UserDetails como null.
        UserDetails userDetails = null;

        // Se o nome de usuário for válido e não houver autenticação já ativa no contexto de segurança...
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Carrega os detalhes do usuário a partir do nome de usuário extraído do token.
            userDetails = userDetailsService.loadUserByUsername(username);
        }

        // Verifica se o token é válido e se o usuário carregado é o correto.
        // Se for válido, criamos um UsernamePasswordAuthenticationToken.
        UsernamePasswordAuthenticationToken authenticationToken = null;
        if (jwtTokenProvider.isTokenValid(jwt, userDetails)) {
            authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            // Configura os detalhes da autenticação (IP, informações da requisição, etc.).
            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        }

        // Define o objeto de autenticação no SecurityContext do Spring Security.
        // Isso autentica o usuário para o contexto da requisição atual.
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        // Continua o processamento da requisição, passando para o próximo filtro na cadeia de filtros.
        filterChain.doFilter(request, response);
    }
}