-- =A port scanner in moonscript =
-- === ASCII BENE 2023-2025 ======
-- ===============================
export VER = "v0.03"

-- Declaration of helper terminal functions --
export sock=require("socket")
--> ANSI color codes
export COL={red: 31, green: 32,brown:33,blue:34,purple: 35,gray: 37,error: 41}


export boldPrint= (s)-> print "\027[1m"..s.."\027[0m"
export italPrint= (s)-> print "\027[3m"..s.."\027[0m"
export ulPrint= (s)->   print "\027[4m"..s.."\027[0m"
export reversePrint=(s)-> print "\027[7m"..s.."\027[0m"
export colPrint=(s,c)-> print "\027[#{c}m"..s.."\027[0m"
--> cRet returns a string with color tokens added unto it.
--> example print(cRet("hi world",COL.red))
export cRet=(s,c)-> return "\027[#{tostring(c)}m"..tostring(s).."\027[0m"
   
-- END --------------------------------------------------------------------------------------------------------------------------------------------

export tinsert=table.insert
export lentbl = (t) -> return #t

-- Class Defs Below =========================================================================================================================

export class PortScanTask
	new: (host,rangelow=1,rangehigh=1024,connect_timeout=1,receive_timeout=5) =>
    @host=host
		@connect_timeout=connect_timeout
		@receive_timeout=receive_timeout
		@ports_to_scan = {}
		@open_ports={}
		@open_ports_reply={}
    for i=rangelow, rangehigh
      tinsert(@ports_to_scan,i)
    @hostip=sock.dns.toip(@host)
		return true

  easy_scan_range: =>
    ulPrint cRet("portscan.moon #{VER} === Port Scanner and other network tools",COL.green)
    reversePrint "Scanning #{@hostip} (#{@host}),#{#@ports_to_scan} ports in queue"
    italPrint "Using connect timeout of #{@connect_timeout} seconds."
		-- TODO Needs delay here !!!
    for iport in *@ports_to_scan
      colPrint "trying to connect to port #{iport} (#{@host})...",COL.blue
      cli=sock\tcp!
      cli\settimeout(@connect_timeout)
      if not cli\connect(@hostip,iport) then
        colPrint "Port #{iport} is closed.",COL.error
        cli\shutdown!
        continue
      else -- if we determine port is open
        colPrint "Port #{iport} is open",COL.green
        @open_ports[iport]=true
        cli\shutdown!
    colPrint "Port scan completed, found \027[7m#{@open_ports} open ports.\027[0m",COL.blue
  
  test_ports_rx: =>
    -- try to receive a reply from all the previously found open ports.
    colPrint "Now trying to receive a reply from #{}",COL.green
    for iport,_ in pairs @open_ports
      cli=sock\tcp!
      cli\settimeout(@receive_timeout)
      cli\connect(@hostip,iport)
      print "trying to receive 32 bytes from remote port : #{iport}"
      if iport == 80 or iport == 443
        cli\send("GET index.html".."\n")
      else
        cli\send(os.time!.."\n")
      rx_from_port=cli\receive(32)
      if rx_from_port != nil
        @open_ports_reply[iport]=rx_from_port
        print "host reply => \n"..cRet(rx_from_port,COL.brown)
      else
        @open_ports_reply[iport]=nil
        print cRet "No reply from host"
      cli\shutdown!


  display_results: =>
    if @open_ports=={} then
      ulPrint "No open port was found."
    else
      ulPrint "Results of scan for #{@hot}(#{@hostip}: ".."#{@open_ports} open ports"
      for openk,openv in *@open_ports_reply
        cRet(openk, COL.green).." => "..cRet(openv,COL.red)


-- Main prog stuff ---------------------------------<<--------------<<---------------------------<<------------------------------<<-----------------

-- Command line interface:
arg = {...}
a_host=arg[1]
a_port_range_start = arg[2]
a_port_range_end = arg[3]
a_timeout=arg[4]
--------------------------------

export p=PortScanTask(a_host,a_port_range_start,a_port_range_end,a_timeout)

p\easy_scan_range!
p\test_ports_rx!
p\display_results!
