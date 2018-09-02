package logparse;

import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.*;
import java.util.*;
import logparse.AuthLogUtil.Alert;

/**
 * Find abusing Domain Admin Privilege using signature based method.
 * 
 * @version 0.1
 * @author Mariko Fujimoto
 */
public class SignaturedDetector {

	// Key: account name, value: list of EventLogData
	private static Map<String, LinkedHashSet<EventLogData>> log;
	private static String outputDirName = null;

	// Initial value for timeCnt
	private static short TIME_CNT = Short.MAX_VALUE;

	private static int EVENT_PROCESS = 4688;
	private static int EVENT_PRIV = 4672;
	private static int EVENT_TGT = 4768;
	private static int EVENT_ST = 4769;
	private static int EVENT_SHARE = 5140;

	// Alert type
	protected enum AlertType {
		NoTGT, MALCMD, ADMINSHARE, PSEXEC,NoADMIN, NoSystemCMD,NONE
	}

	// Alert type and message
	private Map<AlertType, String> alert = null;
	
	// admin account white list
	private List<String> adminWhiteList = null;

	// Suspicious command list
	private List<String> suspiciousCmd = null;

	// account name for detection
	private Set<String> accounts = new LinkedHashSet<String>();
	
	// account name for detection(Domain Admin Privilege accounts)
	private Set<String> adminAccounts = new LinkedHashSet<String>();

	private int detecctTargetcmdCnt = 0;

	private FileWriter filewriter = null;
	private BufferedWriter bw = null;
	private PrintWriter pw = null;

	// Data format
	private static SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

	private int logCnt = 0;
	private int detectedEventNum = 0;
	private int dataNum=0;
	private int infectedNum=0;

	private void readCSV(String filename) {

		try {
			File f = new File(filename);
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			int eventID = -1;
			String date = "";
			LinkedHashSet<EventLogData> evSet = null;
			String accountName = "";
			String clientAddress = "";
			String serviceName = "";
			String processName = "";
			String shredName = "";
			String objectName = "";
			boolean isTargetEvent = false;

			// Max limit for split
			int limit = 0;

			// categorize same operations based on time stamp
			short timeCnt = TIME_CNT;
			Date baseDate = null;
			Date logDate = null;

			while ((line = br.readLine()) != null) {
				int clientPort = 0;
				// Remove tab
				line = line.replaceAll("\\t", "");
				String[] data = line.split(",", 0);
				for (String elem : data) {
					if (line.contains("Microsoft-Windows-Security-Auditing,")) {
						date = data[1];
						eventID = Integer.parseInt(data[3]);
						if (line.contains(String.valueOf(EVENT_TGT)) || line.contains(String.valueOf(EVENT_ST))
								|| line.contains(String.valueOf(EVENT_PRIV))
								|| line.contains(String.valueOf(EVENT_PROCESS))
								|| line.contains(String.valueOf(EVENT_SHARE))) {
							isTargetEvent = true;
							
							try {
								// Get date
								logDate = sdf.parse(date);
								if (EVENT_ST == eventID && null == baseDate) {
									// Grouping logs recorded almost at the same time
									baseDate = sdf.parse(date);
									timeCnt--;
								} else if (null != baseDate) {
									// Calculate time stamp difference
									long logTime = logDate.getTime();
									long baseTime = baseDate.getTime();
									long timeDiff = (baseTime - logTime) / 1000;
									if (timeDiff > 1) {
										timeCnt--;
										baseDate = sdf.parse(date);
									}
								}

							} catch (ParseException e) {
								e.printStackTrace();
							}
						} else {
							isTargetEvent = false;
						}
					} else if (isTargetEvent) {
						if (elem.contains("アカウント名:") || elem.contains("Account Name:")) {
							accountName = parseElement(elem, ":", limit);
							if (accountName.isEmpty()) {
								continue;
							} else {
								accountName = accountName.split("@")[0].toLowerCase();
								if (null == log.get(accountName)) {
									evSet = new LinkedHashSet<EventLogData>();
								} else {
									evSet = log.get(accountName);
								}
									if (EVENT_PRIV == eventID) {
										accounts.add(accountName);
										adminAccounts.add(accountName);
										evSet.add(new EventLogData(date, "", accountName, eventID, 0,
												"", "", timeCnt));
										log.put(accountName, evSet);
										continue;
									}else {
									// extract all users
									accounts.add(accountName);
								}
							}

						} else if (elem.contains("サービス名:") || elem.contains("Service Name:")) {
							serviceName = parseElement(elem, ":", limit);
						} else if (elem.contains("クライアント アドレス:") || elem.contains("Client Address:")
								|| elem.contains("ソース ネットワーク アドレス:") || elem.contains("Source Network Address:")
								|| elem.contains("送信元アドレス:")|| elem.contains("Source Address:")) {
							elem = elem.replaceAll("::ffff:", "");
							clientAddress = parseElement(elem, ":", limit);

						} else if ((elem.contains("クライアント ポート:") || elem.contains("Client Port:")
								|| elem.contains("ソース ポート:"))|| elem.contains("Source Port:")) {
							try {
								clientPort = Integer.parseInt(parseElement(elem, ":", limit));
							} catch (NumberFormatException e) {
								// nothing
							}
							evSet.add(new EventLogData(date, clientAddress, accountName, eventID, clientPort,
									serviceName, processName, timeCnt));
							if (EVENT_SHARE != eventID) {
								// 5140は共有名の情報を取得してから格納する
								log.put(accountName, evSet);
							}
						} else if (elem.contains("オブジェクト名:")|| elem.contains("Object Name:")) {
							objectName = parseElement(elem, ":", 2).toLowerCase();
						} else if ((elem.contains("プロセス名:") || elem.contains("Process Name:"))) {
							processName = parseElement(elem, ":", 2).toLowerCase();
							clientAddress = "";
							EventLogData ev = new EventLogData(date, clientAddress, accountName, eventID, clientPort,
									serviceName, processName, timeCnt);
							ev.setObjectName(objectName);
							evSet.add(ev);
							log.put(accountName, evSet);
							processName = "";
							objectName = "";
						} else if (elem.contains("共有名:")||elem.contains("Share Name:")) {
							EventLogData ev = new EventLogData(date, clientAddress, accountName, eventID, clientPort,
									serviceName, processName, timeCnt);
							shredName = parseElement(elem, ":", 2).toLowerCase();
							ev.setSharedName(shredName);
							evSet.add(ev);
							log.put(accountName, evSet);
							shredName = "";
						}
					}
				}
			}
			br.close();
		} catch (IOException e) {
			System.out.println(e);
		}

	}

	private String parseElement(String elem, String delimiter, int limit) {
		String value = "";
		try {
			String elems[] = elem.trim().split(delimiter, limit);
			if (elems.length >= 2) {
				value = elems[1];
				value = value.replaceAll("\t", "");
			}
		} catch (RuntimeException e) {
			System.out.println(elem);
			e.printStackTrace();
		}
		if (value.isEmpty()) {
			value = "";
		}
		return value;
	}

	private void outputResults(Map map, String outputFileName) {
		try {
			// normal result
			filewriter = new FileWriter(outputFileName, true);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
			pw.println("date,eventID,account,ip,service,process,sharedname,target,alerttype,alertlevel");
			
			System.out.println("Infected accounts and computers:");

			ArrayList<EventLogData> list = null;

			// アカウントごとに処理する
			for (String accountName : accounts) {
				LinkedHashSet<EventLogData> evS = log.get(accountName);
				if (null == evS) {
					continue;
				}
				setClientAddress(evS);

				// Key: client address
				Map<String, LinkedHashSet> kerlog = new LinkedHashMap<String, LinkedHashSet>();

				// Key: client address
				Map<Long, LinkedHashSet> timeBasedlog = new LinkedHashMap<Long, LinkedHashSet>();

				// Group by client address
				for (EventLogData ev : evS) {
					LinkedHashSet<EventLogData> evSet;
					String clientAddress=ev.getClientAddress();
					if (null != kerlog.get(clientAddress)) {
						evSet = kerlog.get(clientAddress);
					} else {
						evSet = new LinkedHashSet<EventLogData>();
					}
					evSet.add(ev);
					kerlog.put(ev.getClientAddress(), evSet);
					this.logCnt++;
				}
				
				for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
						Map.Entry<String, LinkedHashSet> entry = (Map.Entry<String, LinkedHashSet>) it.next();
						String computer=entry.getKey();
						if(!accountName.isEmpty() && !computer.isEmpty()) {
							this.dataNum++;
						}
				}
				// Judge attacks
				if(adminAccounts.contains(accountName)){
					isAbused(kerlog,accountName);
				}
				// Group by timestamp
				list = new ArrayList<EventLogData>(evS);
				Collections.reverse(list);
				for (EventLogData ev : list) {
					LinkedHashSet<EventLogData> evSet;
					if (null != timeBasedlog.get(ev.getTimeCnt())) {
						evSet = timeBasedlog.get(ev.getTimeCnt());
					} else {
						evSet = new LinkedHashSet<EventLogData>();
					}
					evSet.add(ev);
					timeBasedlog.put(ev.getTimeCnt(), evSet);
				}
				outputLogs(timeBasedlog, accountName);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			pw.close();
			try {
				bw.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Judge whether the logs are recorded by attack activities.
	 * If so, 
	 * @param inputDirname
	 * @param outputDirname
	 */
	public void isAbused(Map<String, LinkedHashSet> kerlog, String accountName) {
		// logs are sorted by account and client address
		for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
			boolean isTGTEvent = false;
			boolean isSTEvent = false;
			short isGolden = 0;
			Map.Entry<String, LinkedHashSet> entry = (Map.Entry<String, LinkedHashSet>) it.next();
			String computer=entry.getKey();
			LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();
			LinkedHashMap<Long,Alert> attackTimeCnt = new LinkedHashMap<Long,Alert>();
			for (EventLogData ev : evS) {
				long timeCnt = (ev.getAccountName() + ev.getClientAddress()).hashCode() + ev.getTimeCnt();
				ev.settimeCnt(timeCnt);
				int eventID = ev.getEventID();
				if (eventID == 4768) {
					isTGTEvent = true;
				} else if (eventID == EVENT_ST) {
					isSTEvent = true;
				}
			}
			for (EventLogData ev : evS) {
				int eventID = ev.getEventID();
				if (eventID == 4768) {
					isTGTEvent = true;
				} else if (eventID == EVENT_ST) {
					isSTEvent = true;
				}
			}
			if (!isTGTEvent && isSTEvent) {
				isGolden = 1;
				System.out.println("Account: "+accountName+", Computer: "+computer);
				for (EventLogData ev : evS) {
					if (EVENT_ST == ev.getEventID()) {
						ev.setIsGolden(isGolden);
						ev.setAlertType(AlertType.NoTGT);
						ev.setAlertLevel(Alert.SEVERE);
					}
				}
			}
			
			Set<String> commands = new LinkedHashSet<String>();
			for (EventLogData ev : evS) {
				
				if(ev.getEventID()==EVENT_PRIV &&!this.adminWhiteList.contains(accountName) 
						&& this.adminAccounts.contains(accountName)){
					isGolden = 1;
					ev.setIsGolden(isGolden);
					ev.setAlertType(AlertType.NoADMIN);
					ev.setAlertLevel(Alert.SEVERE);
				}
				
				if (5140 == ev.getEventID()) {
					if (ev.getSharedName().contains("\\c$")) {
						isGolden = 1;
						ev.setIsGolden(isGolden);
						ev.setAlertType(AlertType.ADMINSHARE);
						ev.setAlertLevel(Alert.SEVERE);
					}
				}
				if (EVENT_PROCESS == ev.getEventID()) {
					String command[] = ev.getProcessName().split("\\\\");
					String commandName = "";
					if (null != command) {
						commandName = command[command.length - 1];
					}
					for (String cmd : suspiciousCmd) {
						if (commandName.equals(cmd)) {
							isGolden = 1;
							ev.setIsGolden(isGolden);
							ev.setAlertType(AlertType.MALCMD);
							commands.add(ev.getProcessName());
						}
					}
				}
				
			}
			// Check command
			int detecctcmdCnt = commands.size();
			double commandExecuterate = (double) detecctcmdCnt / this.detecctTargetcmdCnt;
			Alert alertLevel = Alert.NONE;
			if (commandExecuterate >= AuthLogUtil.ALERT_SEVIRE) {
				alertLevel = Alert.SEVERE;
			} else if (commandExecuterate >= AuthLogUtil.ALERT_WARNING) {
				alertLevel = Alert.WARNING;
			} else if (commandExecuterate > 0) {
				alertLevel = Alert.NOTICE;
			}
			for (EventLogData ev : evS) {
				if(ev.getAlertType()==AlertType.MALCMD){
					ev.setAlertLevel(alertLevel);
				}
				if(1==ev.isGolden()){
					if(ev.getClientAddress().isEmpty() && ev.getEventID()!=EVENT_PRIV) {
						ev.setIsGolden((short)0);
						ev.setAlertLevel(Alert.NONE);
						ev.setAlertType(AlertType.NONE);
					} else{
						this.detectedEventNum++;
					}
				}
			}
			// Extract logs recorded at the same time
			for (EventLogData ev : evS) {
				if (1 == ev.isGolden()) {
					attackTimeCnt.put(ev.getTimeCnt(),ev.getAlertLevel());
					if(ev.getAlertLevel()==Alert.NONE){
						ev.setAlertLevel(alertLevel);
					}
				}
			}
			for (EventLogData ev : evS) {
				if (null!=attackTimeCnt.get(ev.getTimeCnt())) {
					if(0==ev.isGolden()){
						isGolden = 1;
						ev.setIsGolden(isGolden);
					}
					if(ev.getAlertLevel()==Alert.NONE){
						ev.setAlertLevel(attackTimeCnt.get(ev.getTimeCnt()));
					}
				}
			}
			if(1==isGolden && !accountName.isEmpty() && !computer.isEmpty()){
				infectedNum++;
				System.out.println("Account: "+accountName+", Computer: "+computer);
			}
		}
	}
	
	private void outputLogs(Map<Long, LinkedHashSet> kerlog, String accountName) {
		for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
			Map.Entry<Long, LinkedHashSet> entry = (Map.Entry<Long, LinkedHashSet>) it.next();
			LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();

			long logTime = 0;
			for (EventLogData ev : evS) {
				try {
					logTime = sdf.parse(ev.getDate()).getTime();
				} catch (ParseException e1) {
					e1.printStackTrace();
				}
				// UNIX Time
				long time = 0;
				try {
					time = sdf.parse(ev.getDate()).getTime();
				} catch (ParseException e) {
					e.printStackTrace();
				}
				pw.println(ev.getDate() + "," + ev.getEventID() + "," + accountName + "," + ev.getClientAddress() + ","
						+ ev.getServiceName() + "," + ev.getProcessName() + "," 
						+ ev.getSharedName() + "," + ev.isGolden() + "," + this.alert.get(ev.getAlertType()) + ","
						+ ev.getAlertLevel());
			}
			
		}

	}

	/**
	 * Parse CSV files exported from event log. Detect possibility of attacks
	 * using Golden Ticket
	 * 
	 * @param inputDirname
	 */
	private void detectGolden(String inputDirname) {
		File dir = new File(inputDirname);
		File[] files = dir.listFiles();

		for (File file : files) {
			String filename = file.getName();
			if (filename.endsWith(".csv")) {
				readCSV(file.getAbsolutePath());
			} else {
				continue;
			}
		}
		outputResults(log, this.outputDirName + "/" + "result.csv");
	}

	private void detelePrevFiles(String outDirname) {
		Path path = Paths.get(outDirname);
		try (DirectoryStream<Path> ds = Files.newDirectoryStream(path, "*.*")) {
			for (Path deleteFilePath : ds) {
				Files.delete(deleteFilePath);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void printUseage() {
		System.out.println("Useage");
		System.out.println(
				"{iputdirpath} {outputdirpath} {suspicious command list file} ({admin list})");
	}

	/**
	 * Read suspicious command list
	 * 
	 * @param inputfilename
	 */
	private void readSuspiciousCmd(String inputfilename) {

		File f = new File(inputfilename);
		suspiciousCmd = new ArrayList<String>();
		try {
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			while ((line = br.readLine()) != null) {
				suspiciousCmd.add(line);
			}
			this.detecctTargetcmdCnt = this.suspiciousCmd.size();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * Read admin list
	 * @param inputfilename
	 */
	private void readAdminList(String inputfilename) {

		File f = new File(inputfilename);
		adminWhiteList = new ArrayList<String>();
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(f));
			String line;
			while ((line = br.readLine()) != null) {
				adminWhiteList.add(line);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void setAlert() {
		this.alert = new HashMap<AlertType, String>();
		alert.put(AlertType.NoTGT, "No TGT request");
		alert.put(AlertType.MALCMD, "Malicious Command");
		alert.put(AlertType.ADMINSHARE, "Administrative Share");
		alert.put(AlertType.PSEXEC, "Psexec used");
		alert.put(AlertType.NoSystemCMD, "Non system command uses sensitive privilege");
		alert.put(AlertType.NoADMIN, "Not in Admin list");
	}

	private void setClientAddress(LinkedHashSet<EventLogData> evS) {
		List<EventLogData> list = new ArrayList<EventLogData>(evS);
		// Sort by time stamp
		Collections.reverse(list);
		String clientAddress = "";
		for (EventLogData ev : list) {
			if (ev.getEventID() == EVENT_ST) {
				clientAddress = ev.getClientAddress();
			} else if (ev.getEventID() == EVENT_PROCESS) {
				if(!clientAddress.isEmpty()){
					ev.setClientAddress(clientAddress);
				}
			}
		}
	}

	private void outputDetectionRate() {
		System.out.println();
		System.out.println("Total amount of events: " + this.logCnt);
		System.out.println("Total amount of accounts & computers: " + this.dataNum);
		System.out.println("TP(event): " + this.detectedEventNum);
		System.out.println("TN(event): " + (this.logCnt - this.detectedEventNum));
		System.out.println("TP(accounts & computers): " + this.infectedNum);
		System.out.println("TN(accounts & computers): " + (this.dataNum - this.infectedNum));
	}

	public static void main(String args[]) throws ParseException {
		SignaturedDetector GoldenTicketDetector = new SignaturedDetector();
		String inputdirname = "";
		String commandFile = "";
		String adminlist = "";
		if (args.length < 3) {
			printUseage();
		} else
			inputdirname = args[0];
		outputDirName = args[1];
		commandFile = args[2];
		if (args.length > 3) {
			adminlist=args[3];
		}
		log = new LinkedHashMap<String, LinkedHashSet<EventLogData>>();
		GoldenTicketDetector.setAlert();
		GoldenTicketDetector.readSuspiciousCmd(commandFile);
		GoldenTicketDetector.readAdminList(adminlist);
		GoldenTicketDetector.detelePrevFiles(outputDirName);
		GoldenTicketDetector.detectGolden(inputdirname);
		GoldenTicketDetector.outputDetectionRate();
	}

}
