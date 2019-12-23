from socket import socket  # import for the TCP Socket object
from json import dumps, loads  # import for turning the packet object into a json string
from random import randint  # import to generate random number encrypting a packet
from sys import getsizeof  # import to get the size of a packet object in bytes
from time import sleep  # import to allow the program to sleep in the timed wait state

key = "IHDoqs7oZoyUVY1g8ivXtfCBYW8QKBgTy46okSL38RYSBIalXnW4AMtfBaoEJODscINVf4wZfInPWCpsBnF0lkz4q4UhiN98aEYw6V347Fv3fh034HUa6VxLcemO8VmjiY6yJjtspdGUaV7EvkG32J9F25G9Kns0ph5kHlFSJgtC3SevdOVwAUKwYMK1DJ2o"  # key used for encryption
end_key_position = len(key) - 1  # variable to hold the position of the last position of the encryption key


class Packet:  # class to represent a TCP packet
    def __init__(self):  # class constructor to set up the object to its default values
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
        random_char = chr(((
                                       random_number * message_length) % 255))  # both the length of the json string and the random number are used to generate a random character that will give the cipher text a bit of randomness especially if the same messsage is sent repeatedly
        encrypted_json_string += random_char  # the random character is the first character of the cipher text however both this character and the key would be needed to decipher the message

        for byte_to_encrypt in json_string:  # loop through the characters in the json string and encrypt each of them
            if current_key_position > end_key_position:  # if the current key position is going to go past the end position of the key, reset the position to 0 as this will stop the program trying to access non existing characters
                current_key_position = 0

            output_byte = ord(byte_to_encrypt) ^ (ord(random_char) ^ ord(
                key[current_key_position]))  # use XOR to encrypt each letter with the random character and the key
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

            output_byte = ord(byte_to_decrypt) ^ (ord(random_char) ^ ord(
                key[current_key_position]))  # use XOR to decrypt each letter with the random character and the key
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

    def setState(self,
                 newState):  # function to change the state of the state machine to the given state name in the parameter
        try:
            self.currentState = self.availableStates[
                newState]  # fetch the object of the desired state from the available state dictionary
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

    def active_open(self):  # function to open the client side of the TCP connection, send a syn packet and shift to the sign sent state
        try:
            print "Opening Connection & Sending SYN Command"
            self.currentContext.socket = socket()  # create a new socket object within the current context
            self.currentContext.socket.connect((self.currentContext.host, self.currentContext.port))  # set the address and port number for the connection, here it will be the loopback address
            self.currentContext.connection_address = self.currentContext.host  # set the connection address to the host address
            if self.currentContext.commands[self.currentContext.command_counter].rstrip() == "SYN":  # if the given command is syn
                packet = Packet()  # create a new packet
                packet.syn_flag = 1  # set the syn flag
                packet.seq_number = self.currentContext.seq_number  # set the seq number
                packet.ack_number = self.currentContext.ack_number  # set the ack number
                self.currentContext.socket.send(packet.to_json())  # send the packet as a json string
                self.currentContext.command_counter += 1  # increase the command counter by 1
                self.currentContext.seq_number += 1  # increase the seq number by 1
                self.currentContext.setState("SYNSENT")  # transition to the syn sent state
                return True
            else:
                print "Command Unavailable In This State"
                return False
        except Exception as err:
            self.currentContext.setState("SYNSENT")  # transition to the syn sent state so that the client can be reset

    def trigger(self):  # states's trigger function to run as soon as the state is changed
        print "Entering Closed State"

        if (self.currentContext.command_counter + 1) <= len(self.currentContext.commands):  # if there are commands left to run, reset the command counter to 0
            self.currentContext.command_counter = 0
        else:
            return True  # else end the demo

        if self.currentContext.connection_address is not 0:  # if the connection address is not 0, indicating an existing connection, reset the TCP connection
            self.currentContext.socket.close()
            self.currentContext.socket = None
            self.currentContext.connection_address = 0
            self.currentContext.seq_number = 0
            self.currentContext.ack_number = 0

        self.currentContext.active_open()  # call to the active open transition
        return True

class SynSentState(State, Transition):  # class to represent the syn sent state of the state machine
    def __init__(self, context):  # constructor to call the superclasses constructor
        State.__init__(self, context)

    def rst(self):  # function to transition to the closed state when the client needs to reset
        print "Received RST Command"
        self.currentContext.setState("CLOSED")  # transition to the closed state
        return True

    def timeout(self):  # function to send a rst packet and transition to the closed state
        print "Timed Out, Resetting"
        packet = Packet()  # create a new packet
        packet.rst_flag = 1  # set the rst flag
        packet.seq_number = self.currentContext.seq_number  # set the seq number
        packet.ack_number = self.currentContext.ack_number  # set the ack number
        self.currentContext.socket.send(packet.to_json())  # send the rst packet
        self.currentContext.setState("CLOSED")  # transition to the closed state
        return True

    def syn_ack(self):  # function to send an ack when a syn ack is received and transition to the established state
        print "Received SYNACK Command"
        if self.currentContext.commands[self.currentContext.command_counter].rstrip() == "ACK":  # if the given command is ack
            print "Sending ACK Command"
            packet = Packet()  # create a new packet
            packet.ack_flag = 1  # set the ack packet
            packet.seq_number = self.currentContext.seq_number  # set the seq number
            packet.ack_number = self.currentContext.ack_number  # set the ack number
            self.currentContext.socket.send(packet.to_json())  # send the ack packet
            self.currentContext.command_counter += 1  # increase the command counter by 1
            self.currentContext.setState("ESTABLISHED")  # transition to the established state
            return True
        else:
            print "Command Unavailable In This State"
            return False

    def trigger(self):  # states's trigger function to run as soon as the state is changed
        print "Entering Syn Sent State"
        while True:
            if self.currentContext.connection_address is 0:  # if there is no connection then the server is not available so send a rst packet
                self.currentContext.rst()
                return True

            go_to_timeout = raw_input("Go To Timeout (y/n) :")
            if go_to_timeout == "y":  # if the client is set to timeout
                self.currentContext.seq_number -= 1  # reverse the seq number to account for the syn packet never getting to the server
                self.currentContext.timeout()  # call the timeout transition
                return True

            raw_data = self.currentContext.socket.recv(1024)  # receive the next json string
            packet = Packet()  # create a new packet
            packet.to_object(raw_data)  # convert the json string to a packet
            if packet.seq_number == self.currentContext.ack_number:  # if the seq number matches the ack number
                if packet.syn_flag is 1 and packet.ack_flag is 1:  # if the syn and ack flags are set
                    self.currentContext.ack_number = packet.seq_number + 1  # update the ack number
                    self.currentContext.syn_ack()  # call the synack number
                    return True


class EstablishedState(State, Transition):  # class to represent the established state of the state machine
    def __init__(self, context):  # constructor to call the superclasses constructor
        State.__init__(self, context)

    def close(self):  # function to send a fin packet and transition to the fin wait one state
        print "All Messages Sent"
        if self.currentContext.commands[self.currentContext.command_counter].rstrip() == "FIN":  # if the given command is fin
            print "Sending FIN Command"
            packet = Packet()  # create a new packet
            packet.fin_flag = 1  # set the fin flag
            packet.seq_number = self.currentContext.seq_number  # set the seq number
            packet.ack_number = self.currentContext.ack_number  # set the ack number
            self.currentContext.socket.send(packet.to_json())  # send the packet as a json string
            self.currentContext.command_counter += 1  # increase the command counter by one
            self.currentContext.seq_number += 1  # increase the seq number by 1
            self.currentContext.setState("FINWAITONE")  # transition to the fin wait one state
            return True
        else:
            print "Command Unavailable In This State"
            return False

    def trigger(self):  # states's trigger function to run as soon as the state is changed
        print "Entering Established State"
        messages_count = 0  # variable to keep track of which message to currently send
        while messages_count < len(self.currentContext.messages_to_send):  # while there is a message to send
            packet = Packet()  # create a new packet
            packet.message = self.currentContext.messages_to_send[messages_count].rstrip()  # set the message
            packet.seq_number = self.currentContext.seq_number  # set the seq number
            packet.ack_number = self.currentContext.ack_number  # set the ack number
            print "Sending Message:", packet.message
            self.currentContext.socket.send(packet.to_json())  # send the packet as a json string
            while True:  # while true keep sending the message until an ack is received
                drop_packet = raw_input("Drop Packet (y/n) :")
                if drop_packet == "n":
                    raw_data = self.currentContext.socket.recv(1024)  # receive the json string
                    packet = Packet()  # create a new packet
                    packet.to_object(raw_data)  # convert the json string to a packet object
                    if packet.seq_number == self.currentContext.ack_number:  # if the syn number is the same as what is expected
                        if packet.ack_flag is 1:  # if the ack flag is set
                            print "Received ACK Command To Confirm Message Was Received"
                            break

                else:
                    print "Message Was Not Received By Server"
                    packet = Packet()  # create a new packet
                    packet.message = self.currentContext.messages_to_send[messages_count].rstrip()  # set the message
                    packet.seq_number = self.currentContext.seq_number  # set the seq number
                    packet.ack_number = self.currentContext.ack_number  # set the ack number
                    print "Resending Message:", packet.message
                    self.currentContext.socket.send(packet.to_json())  # send the packet
            messages_count += 1  # increase the message count by 1
            self.currentContext.seq_number += getsizeof(packet)  # increase the seq number
        self.currentContext.close()  # call the close transition
        return True


class FinWaitOneState(State, Transition):  # class to represent the fin wait one state of the state machine
    def __init__(self, context):  # constructor to call the superclasses constructor
        State.__init__(self, context)

    def ack(self):  # function to transition to the fin wait two state when an ack was received
        print "Received ACK Command"
        self.currentContext.setState("FINWAITTWO")
        return True

    def trigger(self):  # states's trigger function to run as soon as the state is changed
        print "Entering Fin Wait One State"
        while True:
            raw_data = self.currentContext.socket.recv(1024)  # receive the next json string
            packet = Packet()  # create a new packet
            packet.to_object(raw_data)  # convert the json screen to a packet object
            if packet.seq_number == self.currentContext.ack_number:  # if the seq number is as expected
                if packet.ack_flag is 1:  # if the ack flag is set
                    self.currentContext.ack()  # call the ack transition
                    return True


class FinWaitTwoState(State, Transition):  # class to represent the fin wait one state of the state machine
    def __init__(self, context):  # constructor to call the superclasses constructor
        State.__init__(self, context)

    def fin(self):  # function to send an ack and transition to the timed wait state when a fin is received
        print "Received FIN Command"
        if self.currentContext.commands[self.currentContext.command_counter].rstrip() == "ACK":  # if ack is the given command
            print "Sending ACK Command"
            packet = Packet()  # create a new packet
            packet.ack_flag = 1  # set the ack flag
            packet.seq_number = self.currentContext.seq_number  # set the seq number
            packet.ack_number = self.currentContext.ack_number  # set the ack number
            self.currentContext.socket.send(packet.to_json())  # send the packet as a json string
            self.currentContext.command_counter += 1  # increment the command counter
            self.currentContext.setState("TIMEDWAIT")  # transition to the timed wait state
            return True
        else:
            print "Command Unavailable In This State"
            return False

    def trigger(self):  # states's trigger function to run as soon as the state is changed
        print "Entering Fin Wait Two State"
        while True:
            raw_data = self.currentContext.socket.recv(1024)  # receive the next json string
            packet = Packet()  # create a new packet
            packet.to_object(raw_data)  # turn the json string into a packet
            if packet.seq_number == self.currentContext.ack_number:  # if the seq number is as expected
                if packet.fin_flag is 1:  # if the fin flag is set
                    self.currentContext.ack_number = packet.seq_number + 1  # update the ack number
                    self.currentContext.fin()  # call the fin transition
                    return True


class TimedWaitState(State, Transition):  # class to represent the timed wait state of the state machine
    def __init__(self, context):  # constructor to call the superclasses constructor
        State.__init__(self, context)

    def timeout(self):  # function to transition to the closed state when timed out
        print "Timed Out"
        self.currentContext.setState("CLOSED")  # transition to the closed state
        return True

    def trigger(self):  # states's trigger function to run as soon as the state is changed
        print "Entering Timed Wait State"
        time_to_wait = 5
        print "Waiting ", time_to_wait, " Seconds"
        sleep(5)  # wait for any number of seconds
        self.currentContext.timeout()  # call the timeout transition
        return True


class TCPClient(StateContext, Transition):  # class to represent the context for the state machine
    def __init__(self):  # constructor to set all of the variables to default values and start the client by transitioning to the closed state
        self.host = "127.0.0.1"  # variable to hold the desired address to connect to
        self.port = 5000  # variable to hold the desired port number to connect to
        self.connection_address = 0  # variable to hold the address of the server connected to
        self.socket = None  # variable to hold the socket object
        self.seq_number = 0  # variable to hold the seq number
        self.ack_number = 0  # variable to hold the ack number
        # add instances of each state to the available state dictionary
        self.availableStates["CLOSED"] = ClosedState(self)
        self.availableStates["SYNSENT"] = SynSentState(self)
        self.availableStates["ESTABLISHED"] = EstablishedState(self)
        self.availableStates["FINWAITONE"] = FinWaitOneState(self)
        self.availableStates["FINWAITTWO"] = FinWaitTwoState(self)
        self.availableStates["TIMEDWAIT"] = TimedWaitState(self)
        self.commands = []  # list of commands for the client to execute
        self.command_counter = 0  # variable to keep track of which command to execute
        self.messages_to_send = []  # list of messages to send
        self.load_commands("client_commands.txt")  # loads the commands from the text file
        print "Transitioning To The Closed State"
        self.setState("CLOSED")  # transitions to the closed state

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

    def load_commands(self, filename):  # function to load the commands form the text file
        try:
            command_file = open(filename, "r")  # open the text file
        except IOError:
            print "Error!, ", filename, " Does Not Exist!"
            return
        for line in command_file:
            if line[0:4] == "CMD ":  # if the line starts with CMD it is a command and is added to the commands list
                self.commands.append(line[4::])
            elif line[0:4] == "MSG ": # otherwise the line is a message and is added to the messages to send list
                self.messages_to_send.append(line[4::])
        command_file.close()  # close the file


if __name__ == '__main__':
    client = TCPClient()
