#Mauricio Caneo Catalan
#Universidad Finis Terrae
#Asignatura: Seguridad Informatica
#Profesor: Manuel Alba
#Laboratorio Evaluado N°6

#El servidor es Mauricio.
import socket
import sys
import Crypto
from Crypto import Cipher
from Crypto.PublicKey import RSA
import binascii
from Crypto.Cipher import PKCS1_OAEP

sv_socket = socket.socket()
sv_socket.bind(('localhost',8000))
sv_socket.listen()

while True:
    #Se establece la conexion con el cliente.
    conexion, direccion = sv_socket.accept()
    print("Conectado con el cliente", direccion)

    #Recibimos el mensaje del cliente.
    mensaje = conexion.recv(1024).decode()
    print(mensaje)

    #EL SERVIDOR DECIFRA EL MENSAJE ENCRIPTADO DEL CLIENTE.
    #Generar numero aleatorio.
    random_n = Crypto.Random.new().read
    #Generar LLave Privada.
    Clave_Privada = RSA.generate(2048,random_n)
    #Generar LLave Publica.
    Clave_Publica = Clave_Privada.public_key()
    #Exportar llaves.
    Clave_Privada = Clave_Privada.exportKey(format="DER")
    Clave_Publica = Clave_Publica.exportKey(format="DER")
    #Convertir llaves de BIN a UTF8.
    Clave_Privada = binascii.hexlify(Clave_Privada).decode("utf8")
    Clave_Publica = binascii.hexlify(Clave_Publica).decode("utf8")
    print("Enviando Clave publica al cliente...")
    conexion.send(Clave_Publica.encode())
    print("Clave Publica :",Clave_Publica)
    #Importar llaves.
    Clave_Privada = RSA.importKey(binascii.unhexlify(Clave_Privada))
    Clave_Publica = RSA.importKey(binascii.unhexlify(Clave_Publica))

    #Recibe el mensaje cifrado.
    Mensaje_Cifrado = conexion.recv(2048)
    print("Recibiendo mensaje cifrado desde el cliente...")
    
    #Decifrado RSA
    Decifrado = PKCS1_OAEP.new(Clave_Privada)
    Mensaje_Decifrado = Decifrado.decrypt(Mensaje_Cifrado)
    print("\n")

    #Guardar el mensaje decifrado en un archivo txt.
    mensajeSalida = open("mensajerecibido.txt","w+",encoding="utf-8")
    mensajeSalida.write(Mensaje_Decifrado.decode())
    mensajeSalida.close()
    print("Mensaje Descifrado y guardado con exito :D...")

    print("\nDesconectado el cliente", direccion)
    #Cerramos conexion.
    conexion.close()
    sys.exit()
    