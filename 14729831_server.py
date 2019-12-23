from socket import socket  # import for the TCP Socket object
from json import dumps, loads  # import for turning the packet object into a json string
from random import randint  # import to generate random number encrypting a packet
from sys import getsizeof  # import to get the size of a packet object in bytes

key = "IHDoqs7oZoyUVY1g8ivXtfCBYW8QKBgTy46okSL38RYSBIalXnW4AMtfBaoEJODscINVf4wZfInPWCpsBnF0lkz4q4UhiN98aEYw6V347Fv3fh034HUa6VxLcemO8VmjiY6yJjtspdGUaV7EvkG32J9F25G9Kns0ph5kHlFSJgtC3SevdOVwAUKwYMK1DJ2o"  # key used for encryption
end_key_position = len(key) - 1  # variable to hold the position of the last position of the encryption key


class Packet:  # class to represent a TCP packet
    def __init__(self):   # class constructor to set up the object to its default values
        self.message = ""  # variable to hold a message string
        self.syn_flag = 0  # variable to hold the syn flag, set to 0 for unset and 1 for set
        self.ack_flag = 0  # variable to hold the ack flag, set to 0 for unset and 1 for set
        self.fin_flag = 0  # variable to hold the fin flag, set to 0 for unset and 1 for set
        self.rst_flag = 0  # variable to hold the rst flag, set to 0 for unset and 1 for set
        self.ack_number = 0  # variable to hold the ack number
        self.seq_number = 0  # variable to hold the seq number

    def to_json(self):  # function to convert a packet into a json string and then encrypt the string
        # the packet object gets converted into a dictionary first with keys set to represent the variables of the class
        packet = {"message": self.message,
                  "syn_flag": self.syn_flag,
                  "ack_flag": self.ack_flag,
                  "fin_flag": self.fin_flag,
                  "rst_flag": self.rst_flag,
                  "ack_number": self.ack_number,
                  "seq_number": self.seq_number
                  }
        json_string = dumps(packet)  # the pack is converted into a unencrypted json string

        current_key_position = 0  # variable to keep track of which position in the key the stream cipher is currently on
        encrypted_json_string = ""  # variable to record the encrypted json string as it is produced

        random_number = randint(1, 10000)  # random number is generated
        message_length = len(json_string)  # the length of the json string is recorded
        random_char = chr(((random_number*message_length) % 255))  # both the length of the json string and the random number are used to generate a random character that will give the cipher text a bit of randomness especially if the same messsage is sent repeatedly
        encrypted_json_string += random_char  # the random character is the first character of the cipher text however both this character and the key would be needed to decipher the message

        for byte_to_encrypt in json_string:  # loop through the characters in the json string and encrypt each of them
            if current_key_position > end_key_position:  # if the current key position is going to go past the end position of the key, reset the position to 0 as this will stop the program trying to access non existing characters
                current_key_position = 0

            output_byte = ord(byte_to_encrypt) ^ (ord(random_char) ^ ord(key[current_key_position]))  # use XOR to encrypt each letter with the random character and the key
            encrypted_json_string += chr(output_byte)  # add the result of the XOR operation to the output string
            current_key_position += 1  # increment the position in the key by 1

        return encrypted_json_string  # return the encrypted json string

    def to_object(self, json_string):  # function to turn a incoming encrypted json string into a packet object
        current_key_position = 0  # variable to keep track of which position in the key the stream cipher is currently on
        decrypted_json_string = ""  # variable to record the encrypted json string as it is produced

        random_char = json_string[0:1]  # splice the first character off of the incoming string
        encrypted_json_string = json_string[1:]  # store the remaining characters as a string

        for byte_to_decrypt in encrypted_json_string:  # loop through the characters in the json string and decrypt each of them
            if current_key_position > end_key_position:  # if the current key position is going to go past the end position of the key, reset the position to 0 as this will stop the program trying to access non existing characters
                current_key_position = 0

            output_byte = ord(byte_to_decrypt) ^ (ord(random_char) ^ ord(key[current_key_position]))  # use XOR to decrypt each letter with the random character and the key
            decrypted_json_string += chr(output_byte)  # add the result of the XOR operation to the output string
            current_key_position += 1  # increment the position in the key by 1

        # change the decrypted json string into a packet object
        incoming_packet = loads(decrypted_json_string)
        self.message = incoming_packet["message"]
        self.syn_flag = incoming_packet["syn_flag"]
        self.ack_flag = incoming_packet["ack_flag"]
        self.fin_flag = incoming_packet["fin_flag"]
        self.rst_flag = incoming_packet["rst_flag"]
        self.ack_number = incoming_packet["ack_number"]
        self.seq_number = incoming_packet["seq_number"]


class State:  # class to represent the states in the state diagram
    currentContext = None  # variable to hold the current context

    def __init__(self, context):  # constructor for state that will set the current context to the value passed in as a parameter
        self.currentContext = context

    def trigger(self):  # default trigger for all states that is overridden in each state class
        return True


class StateContext:
    state = None  # variable to hold the dictionary key of the current state
    currentState = None  # variable to hold the current state
    availableStates = {}  # a dictionary of available states

    def setState(self, newState):  # function to change the state of the state machine to the given state name in the parameter
        try:
            self.currentState = self.availableStates[newState]  # fetch the object of the desired state from the available state dictionary
            self.state = newState  # record the key used to fetch the desired state
            self.currentState.trigger()  # call the trigger function of the new state
            return True
        except KeyError:  # catch if the desired state name does not exist in the dictionary
            return False

    def getStateIndex(self):  # function to return the state variable of this class
        return self.state


class Transition:  # a class to hold all of the default transitions for the state machine so that if a transition is unavailable in a given state, an error message will be displayed
    def passive_open(self):
        print "Error! Passive Open Transition Not Available!"
        return False

    def syn(self):
        print "Error! Syn Transition Not Available!"
        return False

    def ack(self):
        print "Error! Ack Transition Not Available!"
        return False

    def rst(self):
        print "Error! Rst Transition Not Available!"
        return False

    def syn_ack(self):
        print "Error! Syn Ack Transition Not Available!"
        return False

    def close(self):
        print "Error! Close Transition Not Available!"
        return False

    def fin(self):
        print "Error! Fin Transition Not Available!"
        return False

    def timeout(self):
        print "Error! Timeout Transition Not Available!"
        return False

    def active_open(self):
        print "Error! Active Open Transition Not Available!"
        return False


class ClosedState(State, Transition):  # class to represent the closed state of the state machine
    def __init__(self, context):  # constructor to call the superclasses constructor
        State.__init__(self, context)

    def passive_open(self):  # function to open the server side of the TCP connection and shift to the listen state
        self.currentContext.socket = socket()  # create a new socket object within the current context
        try:
            print "Opening Connection"
            self.currentContext.socket.bind((self.currentContext.host, self.currentContext.port))  # set the address and port number for the connection, here it will be the loopback address
            self.currentContext.socket.listen(1)  # listen for a total of 1 connection at any given time
            self.currentContext.connection, self.currentContext.connection_address = self.currentContext.socket.accept()  # accept the first available incoming connection
        except:
            self.currentContext.setState("CLOSED")  # transition back to the closed state if an error occurs

        self.currentContext.setState("LISTEN")  # transition to the listen state
        return True

    def trigger(self):  # states's trigger function to run as soon as the state is changed
        print "Entering Closed State"

        if self.currentContext.end:  # if the end boolean is set to true, return true which will end the demo
            return True

        if self.currentContext.connection_address is not 0:  # if the connection address is not 0, indicating an existing connection, reset the TCP connection
            self.currentContext.socket.close()
            self.currentContext.connection_address = 0
            self.currentContext.socket = None
            self.currentContext.connection = None
            self.currentContext.seq_number = 0
            self.currentContext.ack_number = 0

        self.currentContext.passive_open()  # call to the passive open transition
        return True


class ListenState(State, Transition):  # class to represent the listen state of the state machine
    def __init__(self, context):  # constructor to call the superclasses constructor
        State.__init__(self, context)

    def syn(self):  # function to send a synack packet and transition to the syn received state
        print "Received SYN Command, Sending SYNACK Command"
        packet = Packet()  # create a new packet
        packet.syn_flag = 1  # set the syn flag
        packet.ack_flag = 1  # set the ack flag
        packet.seq_number = self.currentContext.seq_number  # set the seq number
        packet.ack_number = self.currentContext.ack_number  # set the ack number
        self.currentContext.connection.send(packet.to_json())  # convert the packet to an encrypted json string and send it along the socket
        self.currentContext.seq_number += 1  # increase the seq number by 1 becuase of the sent syn
        self.currentContext.setState("SYNRECEIVED")  # change to the syn received state
        return True

    def trigger(self):  # states's trigger function to run as soon as the state is changed
        print "Entering Listen State"
        while True:
            raw_data = self.currentContext.connection.recv(1024)  # receive the next json string
            packet = Packet()  # create a new packet
            try:
                packet.to_object(raw_data)  # convert the json string into a packet object
            except:
                pass

            if packet.seq_number == self.currentContext.ack_number:  # accept the packet if the seq number is as expected
                if packet.syn_flag is 1:  # if the syn flag is set, and no timeout is to occur, update the ack number and call the syn transition
                    go_to_timeout = raw_input("Go To Timeout (y/n) :")
                    if go_to_timeout == "n":
                        self.currentContext.ack_number = packet.seq_number + 1
                        self.currentContext.syn()
                        return True
                if packet.rst_flag is 1:  # if the rst flag is set, maintain the connection after the server has reset
                    print "Client Timed Out And Reset"
                    self.currentContext.socket.listen(1)
                    self.currentContext.connection, self.currentContext.connection_address = self.currentContext.socket.accept()


class SynReceivedState(State, Transition):  # class to represent the syn received state of the state machine
    def __init__(self, context):  # constructor to call the superclasses constructor
        State.__init__(self, context)

    def ack(self):  # function to change to the established state when an ack has been received
        print "Received ACK Command"
        self.currentContext.setState("ESTABLISHED")
        return True

    def trigger(self):  # states's trigger function to run as soon as the state is changed
        print "Entering Syn Received State"
        while True:
            raw_data = self.currentContext.connection.recv(1024)  # receive the next json string
            packet = Packet()  # create a new packet
            packet.to_object(raw_data)  # convert the json string into a packet object
            if packet.seq_number == self.currentContext.ack_number:  # accept the packet if the seq number is as expected
                if packet.ack_flag is 1:  # if the ack flag is set, call the ack transition
                    self.currentContext.ack()
                    return True

class EstablishedState(State, Transition):  # class to represent the established state of the state machine
    def __init__(self, context):  # constructor to call the superclasses constructor
        State.__init__(self, context)

    def fin(self):  # function to send an ack packet in response to a fin packet and transition to the close wait state
        print "Received FIN Command, Sending ACK Command"
        packet = Packet()  # create a new packet
        packet.ack_flag = 1  # set the ack flag
        packet.seq_number = self.currentContext.seq_number  # set the seq number
        packet.ack_number = self.currentContext.ack_number  # set the ack number
        self.currentContext.connection.send(packet.to_json())  # convert the packet to an encrypted json string and send it along the socket
        self.currentContext.setState("CLOSEWAIT")  # transition to close wait state
        return True

    def trigger(self):  # states's trigger function to run as soon as the state is changed
        print "Entering Established State"
        while True:
            raw_data = self.currentContext.connection.recv(1024)  # receive the next json string
            packet = Packet()  # create a new packet
            packet.to_object(raw_data)  # change the json string to a packet object
            if packet.seq_number == self.currentContext.ack_number:  # accept the packet if the seq number is as expected
                if packet.fin_flag is 1:  # if the fin flag is set, update the ack number and call the fin transition
                    self.currentContext.ack_number = packet.seq_number + 1
                    self.currentContext.fin()
                    return True
                else:  # otherwise if the packet wasnt dropped, send an ack in response
                    drop_packet = raw_input("Drop Packet (y/n) :")
                    if drop_packet == "n":
                        self.currentContext.ack_number = (packet.seq_number + getsizeof(packet))  # update the ack number
                        print "Received Message:", packet.message.rstrip()
                        print "Sending ACK Command To Confirm Message Was Received"
                        packet = Packet()  # create a new packet
                        packet.ack_flag = 1  # set the ack flag
                        packet.seq_number = self.currentContext.seq_number  # set the seq number
                        packet.ack_number = self.currentContext.ack_number  # set the ack number
                        self.currentContext.connection.send(packet.to_json())  # send the packet as a json string along the socket


class CloseWaitState(State, Transition):  # class to represent the close wait state of the state machine
    def __init__(self, context):  # constructor to call the superclasses constructor
        State.__init__(self, context)

    def close(self):  # function to send a fin packet and transition to the last ack state
        print "Closing Connection, Sending FIN Command"
        packet = Packet()  # create a new packet
        packet.fin_flag = 1  # set the fin flag
        packet.seq_number = self.currentContext.seq_number  # set the seq number
        packet.ack_number = self.currentContext.ack_number  # set the ack number
        self.currentContext.connection.send(packet.to_json())  # send the packet as a json string
        self.currentContext.seq_number += 1  # update the seq number
        self.currentContext.setState("LASTACK")  # transition to the last ack state
        return True

    def trigger(self):  # states's trigger function to run as soon as the state is changed
        print "Entering Close Wait State"
        self.currentContext.close()  # call the close transition
        return True


class LastAckState(State, Transition):  # class to represent the close wait state of the state machine
    def __init__(self, context):  # constructor to call the superclasses constructor
        State.__init__(self, context)

    def ack(self):  # function to transition to the closed state when an ack has been received
        print "Received ACK Command"
        self.currentContext.end = True  # sets the end bool to true to end the demo
        self.currentContext.setState("CLOSED")  # trnasitions to the closed state
        return True

    def trigger(self):  # states's trigger function to run as soon as the state is changed
        print "Entering Lack Ack State"
        while True:
            raw_data = self.currentContext.connection.recv(1024)  # receive the next json string
            packet = Packet()  # create a new packet
            packet.to_object(raw_data)  # change the json string to a packet object
            if packet.seq_number == self.currentContext.ack_number:  # if the seq number matches the expected ack number
                if packet.ack_flag is 1:  # if the ack flag is set, call if the ack transition
                    self.currentContext.ack()
                    return True


class TCPServer(StateContext, Transition):  # class to represent the context for the state machine
    def __init__(self):  # constructor to set all of the variables to default values and start the server by transitioning to the closed state
        self.host = "127.0.0.1"  # variable to hold the desired address to bind to the socket
        self.port = 5000  # variable to hold the desired port number to bind to the socket
        self.connection_address = 0  # variable to hold the address of the connected client
        self.socket = None  # variable to hold the socket object
        self.connection = None  # variable to hold the connection object
        self.seq_number = 0  # variable to hold the seq number
        self.ack_number = 0  # variable to hold the ack number
        self.end = False  # variable to hold the end bool
        # add instances of each state to the available state dictionary
        self.availableStates["CLOSED"] = ClosedState(self)
        self.availableStates["LISTEN"] = ListenState(self)
        self.availableStates["SYNRECEIVED"] = SynReceivedState(self)
        self.availableStates["ESTABLISHED"] = EstablishedState(self)
        self.availableStates["CLOSEWAIT"] = CloseWaitState(self)
        self.availableStates["LASTACK"] = LastAckState(self)
        print "Transitioning To Closed State"
        self.setState("CLOSED")  # transition to the closed state

    # functions to call the transition functions for the state that the machine is current in
    def passive_open(self):
        return self.currentState.passive_open()

    def syn(self):
        return self.currentState.syn()

    def ack(self):
        return self.currentState.ack()

    def rst(self):
        return self.currentState.rst()

    def syn_ack(self):
        return self.currentState.syn_ack()

    def close(self):
        return self.currentState.close()

    def fin(self):
        return self.currentState.fin()

    def timeout(self):
        return self.currentState.timeout()

    def active_open(self):
        return self.currentState.active_open()


if __name__ == '__main__':
    server = TCPServer()
