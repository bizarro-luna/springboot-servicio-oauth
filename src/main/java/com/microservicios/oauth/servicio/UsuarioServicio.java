package com.microservicios.oauth.servicio;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.microservicios.commons.usuario.entity.Usuario;
import com.microservicios.oauth.client.UsuarioFeignClient;

import brave.Tracer;
import feign.FeignException;





/**
 * Clase que implementa UserDetailService, para implementar nuestra propia base de datos
 * @author Hector
 *
 */
@Service
public class UsuarioServicio implements IUsuarioService, UserDetailsService {

	
	private Logger log= LoggerFactory.getLogger(UsuarioServicio.class);
	
	
	/**
	 * Cliente feign para usuario
	 */
	@Autowired
	private UsuarioFeignClient cliente;
	
	@Autowired
	private Tracer tracer;
	
	
	
	
	/**
	 * Metodo para cargar el usuario por medio del username
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		try {

			Usuario usuario = cliente.findByUsername(username);

			List<GrantedAuthority> roles = usuario.getRoles().stream()
					.map(rol -> new SimpleGrantedAuthority(rol.getNombre()))
					.peek(authority -> log.info("Rol :" + authority.getAuthority())).collect(Collectors.toList());

			log.info("Usuario autenticado: " + username);
			return new User(usuario.getUsername(), usuario.getPassword(), usuario.getEnabled(), true, true, true,
					roles);

		} catch (FeignException e) {
			String mensajeError="Error en el login,El usuario no econtrado: " + username;
			log.error(mensajeError);
			//Mensaje para exportar a zipkin
			tracer.currentSpan().tag("error.mensaje", mensajeError+" : "+ e.getMessage());
			throw new UsernameNotFoundException(mensajeError);
		}
	}


	/*
	 * (non-Javadoc)
	 * @see com.microservicios.oauth.servicio.IUsuarioService#findByUsername(java.lang.String)
	 */
	@Override
	public Usuario findByUsername(String username) {
		return cliente.findByUsername(username);
	}


	/*
	 * (non-Javadoc)
	 * @see com.microservicios.oauth.servicio.IUsuarioService#update(com.microservicios.commons.usuario.entity.Usuario, java.lang.Long)
	 */
	@Override
	public Usuario update(Usuario usuario, Long id) {
		return cliente.update(usuario, id);
	}

}
