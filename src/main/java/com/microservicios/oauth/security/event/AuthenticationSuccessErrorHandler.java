package com.microservicios.oauth.security.event;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.microservicios.commons.usuario.entity.Usuario;
import com.microservicios.oauth.servicio.IUsuarioService;
import com.microservicios.oauth.servicio.UsuarioServicio;

import brave.Tracer;
import feign.FeignException;


/**
 * Clase de evento para manejar las acciones en autenticacion en spring security
 * @author Hector
 *
 */
@Component
public class AuthenticationSuccessErrorHandler implements AuthenticationEventPublisher {

	/**
	 * Log
	 */
	private Logger log= LoggerFactory.getLogger(AuthenticationSuccessErrorHandler.class);
	
	
	@Autowired
	private IUsuarioService servicioUsuario;
	
	
	@Autowired
	private Tracer tracer;
	
	
	/**
	 * Metodo para cuando el evento es correcto
	 */
	@Override
	public void publishAuthenticationSuccess(Authentication authentication) {
		UserDetails user= (UserDetails) authentication.getPrincipal();
		//se puede usar para guardar registro en la base de datos o bitacora
		String mensaje= "Success Login: "+user.getUsername();
		System.out.println(mensaje);
		log.info(mensaje);
		
		try {
			Usuario usuario = servicioUsuario.findByUsername(authentication.getName());
			if (usuario.getIntentos() != null && usuario.getIntentos() > 0) {
				usuario.setIntentos(0);
				servicioUsuario.update(usuario, usuario.getId());
			}
		} catch (FeignException e) {
			log.error(String.format("El usuario %s no existe en el sistema success", authentication.getName()));
		}
		
	}

	
	/**
	 * Cuando el evento de acceso es incorrecto
	 */
	@Override
	public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
		String mensaje= "Error en el Login: "+exception.getMessage();
		System.out.println(mensaje);
		log.error(mensaje);
		
        try {
        	StringBuilder errors= new StringBuilder();
        	errors.append(mensaje);
        	//logica por si el usuario se equivoco mas de tres veces  de contraseña
        	Usuario usuario= servicioUsuario.findByUsername(authentication.getName());
        	if(usuario.getIntentos()==null) {
        		usuario.setIntentos(0);
        	}
        	log.info(String.format("Intentos actual es de  %s", usuario.getIntentos()));
        	usuario.setIntentos(usuario.getIntentos()+1);
        	log.info(String.format("Intentos despues es de %s", usuario.getIntentos()));
        	
        	errors.append(" - "+String.format("Intentos despues es de %s", usuario.getIntentos()));
        	
        	if(usuario.getIntentos()>=3) {
        		log.error(String.format("El usuario %s des-hababilitado por tres intentos", usuario.getUsername()));
        		errors.append(" - "+String.format("El usuario %s des-hababilitado por tres intentos", usuario.getUsername()));
        		usuario.setEnabled(false);
        	}
        	
        	servicioUsuario.update(usuario, usuario.getId());
        	
        	
        	tracer.currentSpan().tag("error.mensaje", errors.toString());
        	
        }catch(FeignException e) {
        									//un patron para modificar por el valor
        	log.error(String.format("El usuario %s no existe en el sistema", authentication.getName()));
        }
		
	}

}
