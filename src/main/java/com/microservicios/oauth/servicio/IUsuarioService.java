package com.microservicios.oauth.servicio;


import com.microservicios.commons.usuario.entity.Usuario;

/**
 * Intefaz para negocio del Ususario
 * @author Hector
 *
 */
public interface IUsuarioService {
	
	/**
	 * Metodo para obtener el usuario por medio del nombre
	 * @param username
	 * @return
	 */
	Usuario findByUsername(String username);
	
	/**
	 * Metodo para actualizar a el usuario
	 * @param usuario
	 * @param id
	 * @return
	 */
	public Usuario update(Usuario usuario,Long id);

}
