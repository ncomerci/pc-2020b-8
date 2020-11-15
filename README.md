# Proxy SOCKSv5 - PDC - Grupo 8 - 20202Q

el protocolo SOCKSv5 permite atravesar de forma segura y transparente firewalls que aíslan una red. Esta implementación cuenta con las siguientes características:

- Atiende a múltiples clientes en forma concurrente.
- Los clientes pueden autenticarse utilizando un usuario y una contraseña como lo indica el RFC 1929.
- Soporta conexiones a direcciones IPv4, IPv6 o FQDN. 
- Cuenta con un protocolo de configuracion para monitorear la operación del sistema y cambiar la configuración del servidor en tiempo de ejecución. 
- Mantiene un registro de acceso que permite dar a conocer quien se conectó, a qué sitio y cuándo.  
- Monitorea el tráfico y genera un registro de credenciales de acceso para los protocolos HTTP y POP3. 



### Instalación

Requerimientos previos:
- Un compilador de C ([GCC](https://gcc.gnu.org/) o [CLANG](https://clang.llvm.org/)) 
- La herramienta ```make```

Compilación del proyecto e inicio del proxy

```sh
$ git clone git@bitbucket.org:itba/pc-2020b-8.git
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
https_proxy=localhost:1080 wget https://apache.zero.com.ar//jmeter/binaries/apache-jmeter-5.3.zip
```
```sh
ncat -C --proxy-type socks5 --proxy localhost:1080 www.google.com 80
```
img firefox


### Development

Want to contribute? Great!

Dillinger uses Gulp + Webpack for fast developing.
Make a change in your file and instantaneously see your updates!

Open your favorite Terminal and run these commands.

First Tab:
```sh
$ node app
```

Second Tab:
```sh
$ gulp watch
```

(optional) Third:
```sh
$ karma test
```
#### Building for source
For production release:
```sh
$ gulp build --prod
```
Generating pre-built zip archives for distribution:
```sh
$ gulp build dist --prod
```
### Docker
Dillinger is very easy to install and deploy in a Docker container.

By default, the Docker will expose port 8080, so change this within the Dockerfile if necessary. When ready, simply use the Dockerfile to build the image.

```sh
cd dillinger
docker build -t joemccann/dillinger:${package.json.version} .
```
This will create the dillinger image and pull in the necessary dependencies. Be sure to swap out `${package.json.version}` with the actual version of Dillinger.

Once done, run the Docker image and map the port to whatever you wish on your host. In this example, we simply map port 8000 of the host to port 8080 of the Docker (or whatever port was exposed in the Dockerfile):

```sh
docker run -d -p 8000:8080 --restart="always" <youruser>/dillinger:${package.json.version}
```

Verify the deployment by navigating to your server address in your preferred browser.

```sh
127.0.0.1:8000
```
