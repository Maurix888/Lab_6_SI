#Mauricio Caneo Catalan
#Universidad Finis Terrae
#Asignatura: Seguridad Informatica
#Profesor: Manuel Alba
#Laboratorio Evaluado N°6

#El cliente es Jonathan.
import socket
import sys
import Crypto
from Crypto import Cipher
from Crypto.PublicKey import RSA
import binascii
from Crypto.Cipher import PKCS1_OAEP


cl_socket = socket.socket()
cl_socket.connect(('localhost',8000))

while True:
    #Escribimos el mensaje al servidor.
    mensaje = ("Conectando el cliente...")
    cl_socket.send(mensaje.encode())
    #EL CLIENTE CIFRA EL MENSAJE Y LO ENVIA AL SERVIDOR.
    #Leer Archivo txt con el mensaje a cifrar.
    #Abrir el archivo de texto.
    MensajeEntrada = open("mensajeentrada.txt","r+",encoding="utf-8")
    #Lee el texto con el mensaje.
    mensajeentrada = MensajeEntrada.read()
    #Cierra el archivo de texto.
    MensajeEntrada.close

    #Recibir clave publica generada en el servidor.
    Clave_Publica = cl_socket.recv(2048).decode()
    print("Recibiendo clave publica del servidor...")
    print("Clave publica : ", Clave_Publica)

    #Encriptar el mensaje con RSA.
    #Mensaje a cifrar.
    mensaje = mensajeentrada
    mensaje = mensaje.encode()

    #Importar clave publica.
    Clave_Publica = RSA.importKey(binascii.unhexlify(Clave_Publica))

    #Cifrado RSA.
    cifrado = PKCS1_OAEP.new(Clave_Publica)
    Mensaje_Cifrado = cifrado.encrypt(mensaje)
    print("\n")
    print("Mensaje Cifrado RSA: ",Mensaje_Cifrado)

    #Enviar el mensaje encriptado al servidor.
    cl_socket.send(Mensaje_Cifrado)

    #Cerramos el socket del cliente.
    print("\nCerrando Socket...")
    cl_socket.close()
    sys.exit()
