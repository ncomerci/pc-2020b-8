# Proxy SOCKSv5 - PDC - Grupo 8 - 20202Q

el protocolo SOCKSv5 permite atravesar de forma segura y transparente firewalls que aíslan una red. Esta implementación cuenta con las siguientes características:

- Atiende a múltiples clientes en forma concurrente.
- Los clientes pueden autenticarse utilizando un usuario y una contraseña como lo indica el RFC 1929.
- Soporta conexiones a direcciones IPv4, IPv6 o FQDN.
- Resuelve los FQDN mediante consulta DoH (DNS over HTTP)
- Cuenta con un protocolo de configuracion para monitorear la operación del sistema y cambiar la configuración del servidor en tiempo de ejecución. 
- Mantiene un registro de acceso que permite dar a conocer quien se conectó, a qué sitio y cuándo.  
- Monitorea el tráfico y genera un registro de credenciales de acceso para los protocolos HTTP y POP3. 



### Instalación

Requerimientos previos:
- Un compilador de C ([GCC](https://gcc.gnu.org/) o [CLANG](https://clang.llvm.org/)) 
- La herramienta ```make```

Compilación del proyecto e inicio del proxy

```sh
$ git clone https://github.com/ncomerci/pc-2020b-8.git
$ cd pc-2020b-8
$ make all
$ ./socks5d
```

### Guía de uso

Para ver todos los comandos soportados por el proxy, ejecute el siguiente comando:
```sh
$ ./socks5d -h
```
Por defecto, el proxy escucha en el puerto 1080 en la dirección 0.0.0.0 para IPv4 y en :: para IPv6. Por otro lado, para conexiones destinadas a configuración del proxy escucha en el puerto 8080 en 127.0.0.1.

Para comenzar a utilizarlo se debe configurar el programa que se desea utilizar para que deriven los pedidos de conexión al proxy. A continuación se listan algunos ejemplos de para curl, wget, ncat y firefox con los valores de configuración por defecto:

```sh
curl -x socks5://localhost:1080 www.google.com
```
o en caso de querer que el proxy resuelva la dirección solicitada, ejecutar:
```sh
curl -x socks5h://localhost:1080 www.google.com
```
```sh
https_proxy=localhost:1080 wget https://apache.zero.com.ar/jmeter/binaries/apache-jmeter-5.3.zip
```
```sh
ncat -C --proxy-type socks5 --proxy localhost:1080 www.google.com 80
```
En firefox: 
```Preferences > Network Settings```
![firefox](https://lh3.googleusercontent.com/PQo6tOYVqpknOVaIaK1N1Bk4ir3PgG8JTA9Ni-KgXvS8wBLfq8artlK2_VfGji9LJ0QRlC8UqI8lhugRHicvp7knlV53ay8bzigR7rDPkqzJ-n_vX8NVQFzT-LBFDjhJ_kEtLUmzFg=w2400)

### Cliente de configuración del proxy

Para compilar el cliente de configuración del proxy, ejecute el siguiente comando:

```sh
$ make clnt
```
Para ver todos los comandos soportados por el cliente, ejecute el siguiente comando:
```sh
$ ./client/client -h
```
Para acceder a la configuración y a las métricas del proxy en tiempo de ejecución, ejecute el cliente e ingrese las credenciales del usuario administrador, que por defecto son admin:admin (asegurarse que el proxy esté corriendo en otra terminal).

Una vez dentro, se ve el siguiente menú interactivo:

```
01. (GET) transefered bytes
02. (GET) historical connections
03. (GET) concurrent connections
04. (GET) users list

05. (SET) add new users
06. (SET) remove user
07. (SET) change password to an user
08. (SET) enable/disable password sniffer
09. (SET) DOH IP
10. (SET) DOH port
11. (SET) DOH host
12. (SET) DOH path
13. (SET) DOH query
14. QUIT

Choose an option:
```

Las acciones que realizan cada opción son:

1. Obtiene el total de bytes transferidos desde el inicio de la ejecución del proxy (se computan cada vez que el proxy realiza la syscall send).
2. Obtiene el total de conexiones que hubo desde el inicio de la ejecución del proxy.
3. Obtiene el total de conexiones activas en el proxy en ese momento.
4. Obtiene una lista de usuarios registrados en el proxy (Máxima capacidad: 10 usuarios).
5. Agrega un nuevo usuario indicando ```username```y ```password```.
6. Elimina un usuario indicando el ```username```.
7. Cambia la contraseña de un usuario.
8. Habilita o deshabilita el sniffer de contraseñas HTTP y POP3.
9. Permite cambiar la dirección IP del servidor DoH (por defecto 127.0.0.1).
10. Permite cambiar el puerto del servidor DoH (por defecto 8053).
11. Permite cambiar el host del servidor DoH (por defecto localhost).
12. Permite cambiar el path del servidor DoH (por defecto /getnsrecord).
13. Permite cambiar la query del servidor DoH (por defecto ?dns=).
14. Envía el comando de cierre de conexión al proxy y termina la ejecución.

### Ejemplo de ejecución de tests
```sh
$ ./test/auth_test.out
```

### Limpieza de los archivos objeto
```sh
$ make clean
```
