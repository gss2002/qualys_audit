package com.qualys.audit;


import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.text.Normalizer;
import java.util.List;

import org.apache.commons.lang.StringUtils;

import com.qualys.audit.data.*;




public class ProcessQualysXML{

	public static void main(String[] args) {
		// TODO Auto-generated method stub
   	 	long currentTime = System.currentTimeMillis();
   	 	String loadTime = Long.toString(currentTime);
		XMLParser xmlp = new XMLParser();
		String strXMLFilePath = "C:/DATA/git/auditxml2hdp/test_data/scanreport.xml";
		//if (args != null ) {
		//	strXMLFilePath=args[0];
		//}
		ASSETDATAREPORT assetReport = xmlp.readXML(strXMLFilePath);
		//ReportDataTable Partition
		if (assetReport != null) {
			HEADER headerObj = assetReport.getHEADER();
			if (headerObj  != null ){	
			    StringBuffer reportData = new StringBuffer();
			    reportData.setLength(0);

				String strGenTime = removeBadChars(assetReport.getHEADER().getGENERATIONDATETIME());
				String strCompany = removeBadChars(assetReport.getHEADER().getCOMPANY());
				String strTemplate = removeBadChars(assetReport.getHEADER().getTEMPLATE());
				RISKSCORESUMMARY riskScoreObj = assetReport.getHEADER().getRISKSCORESUMMARY();
				String strAvgSecRisk = "NULL";
				String strBizRisk = "NULL";
				String strTotalVulns = "NULL";
				if (riskScoreObj != null) {
					strAvgSecRisk = removeBadChars(assetReport.getHEADER().getRISKSCORESUMMARY().getAVGSECURITYRISK());
					strBizRisk = removeBadChars(assetReport.getHEADER().getRISKSCORESUMMARY().getBUSINESSRISK());
					strTotalVulns = removeBadChars(assetReport.getHEADER().getRISKSCORESUMMARY().getTOTALVULNERABILITIES());
				} 

				reportData.append(strGenTime);
				reportData.append("\t");
				reportData.append(strCompany);
				reportData.append("\t");
				reportData.append(strTemplate);
				reportData.append("\t");
				reportData.append(strAvgSecRisk);
				reportData.append("\t");
				reportData.append(strBizRisk);
				reportData.append("\t");
				reportData.append(strTotalVulns);
				reportData.append("\t");
				reportData.append(loadTime);
				try {
					PrintWriter out = new PrintWriter("reportdata.txt");
					out.println(reportData.toString());
					out.close();
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				StringBuffer reportDataHive = new StringBuffer();
				reportDataHive.setLength(0);
				reportDataHive.append("use peaudit;\n");
				reportDataHive.append("create table IF NOT EXISTS qualys_reportdata (GENERATIONDATETIME string,"+
							"COMPANY string, TEMPLATE string, AVGSECURITYRISK string,BUSINESSRISK string, TOTALVULNERABILITIES string, loadTime string "+	
						") ROW FORMAT DELIMITED FIELDS TERMINATED BY '\\t' stored as TEXTFILE;\n");
				reportDataHive.append("LOAD DATA LOCAL INPATH './reportdata.txt' INTO TABLE qualys_reportdata;");
				try {
					PrintWriter out = new PrintWriter("reportdata.hql");
					out.println(reportDataHive.toString());
					out.close();
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				





				//Table userAssets Partitions

				TARGET rptTarget = assetReport.getHEADER().getTARGET();
				if (rptTarget != null) {
					PrintWriter out = null;
					try {
						out = new PrintWriter("userassetgroups.txt");
					} catch (FileNotFoundException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					StringBuffer userAssetGroupsData = new StringBuffer();

					List<String> userAssetGroups = rptTarget.getUSERASSETGROUPS().getASSETGROUPTITLE();
					for (int uag = 0; uag < userAssetGroups.size(); uag++) {
						userAssetGroupsData.setLength(0);
						String strUag = removeBadChars(userAssetGroups.get(uag));
						userAssetGroupsData.append(strUag);
						out.println(userAssetGroupsData.toString());
					}
					out.close();
					
					StringBuffer userAssetGroupsDataHive = new StringBuffer();
					userAssetGroupsDataHive.setLength(0);
					userAssetGroupsDataHive.append("use peaudit;\n");
					userAssetGroupsDataHive.append("create table IF NOT EXISTS qualys_userassetgroups (ASSETGROUPTITLE string"+
							") partitioned by (loadtime string) ROW FORMAT DELIMITED FIELDS TERMINATED BY '\\t' stored as TEXTFILE;\n");
					userAssetGroupsDataHive.append("LOAD DATA LOCAL INPATH './userassetgroups.txt' INTO TABLE qualys_userassetgroups PARTITION (loadtime='"+loadTime+"');");
					try {
						PrintWriter out2 = new PrintWriter("userassetgroups.hql");
						out2.println(userAssetGroupsDataHive.toString());
						out2.close();
					} catch (FileNotFoundException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}


				//Table CombinedIPList Partitions
				COMBINEDIPLIST combinedIpListObj = rptTarget.getCOMBINEDIPLIST();
				if (combinedIpListObj != null) {
					PrintWriter out = null;
					try {
						out = new PrintWriter("combinediplist.txt");
					} catch (FileNotFoundException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					StringBuffer combinedIpListData = new StringBuffer();
					List<RANGE> combinedIpList = rptTarget.getCOMBINEDIPLIST().getRANGE();
					for (int uil = 0; uil < combinedIpList.size(); uil++) {
						combinedIpListData.setLength(0);
						String startRange = removeBadChars(combinedIpList.get(uil).getSTART());
						String stopRange = removeBadChars(combinedIpList.get(uil).getEND());
						String networkId = removeBadChars(combinedIpList.get(uil).getNetworkId());
						combinedIpListData.append(startRange);
						combinedIpListData.append("\t");
						combinedIpListData.append(stopRange);
						combinedIpListData.append("\t");
						combinedIpListData.append(networkId);
						out.println(combinedIpListData.toString());

					}
					out.close();
					
					StringBuffer combinedIpListDataHive = new StringBuffer();
					combinedIpListDataHive.setLength(0);
					
					combinedIpListDataHive.append("use peaudit;\n");

					combinedIpListDataHive.append("create table IF NOT EXISTS qualys_combinediplist (startRange string,"+
							"stopRange string, networkId string"+
							") partitioned by (loadtime string) ROW FORMAT DELIMITED FIELDS TERMINATED BY '\\t' stored as TEXTFILE;\n");
					combinedIpListDataHive.append("LOAD DATA LOCAL INPATH './combinediplist.txt' INTO TABLE qualys_combinediplist PARTITION (loadtime='"+loadTime+"');");
					try {
						PrintWriter out2 = new PrintWriter("combinediplist.hql");
						out2.println(combinedIpListDataHive.toString());
						out2.close();
					} catch (FileNotFoundException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}

				
				
				//Table UserIpList Partitions
				USERIPLIST userIpListObj = rptTarget.getUSERIPLIST();
				if (userIpListObj != null) {
					PrintWriter out = null;
					try {
						out = new PrintWriter("useriplist.txt");
					} catch (FileNotFoundException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					List<RANGE> userIpList = userIpListObj.getRANGE();
					StringBuffer userIpListData = new StringBuffer();

					for (int uil = 0; uil < userIpList.size(); uil++) {
						userIpListData.setLength(0);
						String startRange = removeBadChars(userIpList.get(uil).getSTART());
						String stopRange = removeBadChars(userIpList.get(uil).getEND());
						String networkId = removeBadChars(userIpList.get(uil).getNetworkId());
						userIpListData.append(startRange);
						userIpListData.append("\t");
						userIpListData.append(stopRange);
						userIpListData.append("\t");
						userIpListData.append(networkId);
						out.println(userIpListData.toString());

					}
					out.close();
					StringBuffer userIpListDataHive = new StringBuffer();
					userIpListDataHive.setLength(0);
					userIpListDataHive.append("use peaudit;\n");
					userIpListDataHive.append("create table IF NOT EXISTS qualys_useriplist (startRange string,"+
							"stopRange string, networkId string"+
							") partitioned by (loadtime string) ROW FORMAT DELIMITED FIELDS TERMINATED BY '\\t' stored as TEXTFILE;\n");
					userIpListDataHive.append("LOAD DATA LOCAL INPATH './useriplist.txt' INTO TABLE qualys_useriplist PARTITION (loadtime='"+loadTime+"');");
					try {
						PrintWriter out2 = new PrintWriter("useriplist.hql");
						out2.println(userIpListDataHive.toString());
						out2.close();
					} catch (FileNotFoundException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}

				//AssetTagList Tables Partitions
				ASSETTAGLIST assetTagListObj = rptTarget.getASSETTAGLIST();
				if (assetTagListObj != null ){
					EXCLUDEDTAGS excludedAssetTagListObj = rptTarget.getASSETTAGLIST().getEXCLUDEDTAGS();
					if (excludedAssetTagListObj != null) {
						List<String> assetTagListExcluded = rptTarget.getASSETTAGLIST().getEXCLUDEDTAGS().getASSETTAG();
					}
					INCLUDEDTAGS includedAssetTagListObj = rptTarget.getASSETTAGLIST().getINCLUDEDTAGS();
					if (includedAssetTagListObj != null) {
						List<String> assetTagListIncluded = rptTarget.getASSETTAGLIST().getINCLUDEDTAGS().getASSETTAG();
					}
				}
			}



			//HostRisk Table Partition
			RISKSCOREPERHOST riskScoreHostObj = assetReport.getRISKSCOREPERHOST();
			if (riskScoreHostObj != null) {
				PrintWriter out = null;
				try {
					out = new PrintWriter("riskscoreperhost.txt");
				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				StringBuffer riskScorePerHostData = new StringBuffer();

				List<HOSTS> riskHostList = assetReport.getRISKSCOREPERHOST().getHOSTS();
				for (int irh = 0; irh < riskHostList.size(); irh++) {
					riskScorePerHostData.setLength(0);
					IPADDRESS ipAddr = riskHostList.get(irh).getIPADDRESS();
					String strIpAddr = "NULL";
					if (ipAddr != null) {
						strIpAddr = removeBadChars(ipAddr.getContent());
					} 
					String strSecRisk = removeBadChars(riskHostList.get(irh).getSECURITYRISK());
					String strHostTotalVulns = removeBadChars(riskHostList.get(irh).getTOTALVULNERABILITIES());
					riskScorePerHostData.append(strIpAddr);
					riskScorePerHostData.append("\t");
					riskScorePerHostData.append(strSecRisk);
					riskScorePerHostData.append("\t");
					riskScorePerHostData.append(strHostTotalVulns);
					out.println(riskScorePerHostData.toString());
				}
				out.close();
				StringBuffer riskScorePerHostDataHive = new StringBuffer();
				riskScorePerHostDataHive.setLength(0);
				riskScorePerHostDataHive.append("use peaudit;\n");
				riskScorePerHostDataHive.append("create table IF NOT EXISTS qualys_riskscoreperhost (IPADDRESS string,"+
						"SECURITYRISK string, TOTALVULNERABILITIES string"+
						") partitioned by (loadtime string) ROW FORMAT DELIMITED FIELDS TERMINATED BY '\\t' stored as TEXTFILE;\n");
				riskScorePerHostDataHive.append("LOAD DATA LOCAL INPATH './riskscoreperhost.txt' INTO TABLE qualys_riskscoreperhost PARTITION (loadtime='"+loadTime+"');");
				try {
					PrintWriter out2 = new PrintWriter("riskscoreperhost.hql");
					out2.println(riskScorePerHostDataHive.toString());
					out2.close();
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			
			//Vulnerability Details (Glossary) Table
			GLOSSARY vulnGlossary = assetReport.getGLOSSARY();
			
			if (vulnGlossary != null) {				
				PrintWriter out = null;
				try {
					out = new PrintWriter("vulndetailslist.txt");			
				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			
			
			StringBuffer vulnDetailsList = new StringBuffer();
			
		    List<VULNDETAILS> vulnDetails = assetReport.getGLOSSARY().getVULNDETAILSLIST().getVULNDETAILS();
			
			for (int vd = 0; vd < vulnDetails.size(); vd++) {
				vulnDetailsList.setLength(0);
				VULNDETAILS vulnDetail = vulnDetails.get(vd);
				String strCategory = vulnDetail.getCATEGORY();
				//String strId = vulnDetail.getId();
				String strImpact = removeBadChars(vulnDetail.getIMPACT());
				//String impactComment = vulnDetail.getIMPACTCOMMENT();
				String strLastUpdateDate = vulnDetail.getLASTUPDATE();
				String strPciFlag = vulnDetail.getPCIFLAG();
				String strSeverity = vulnDetail.getSEVERITY();
				String strSolution = removeBadChars(vulnDetail.getSOLUTION());
				String strThreat = removeBadChars(vulnDetail.getTHREAT());
				String strTitle = removeBadChars(vulnDetail.getTITLE());
				
				//CVE ID concatenation
				StringBuffer strCveIds = new StringBuffer();
				strCveIds.setLength(0);
				if (vulnDetail.getCVEIDLIST() != null){
					List<CVEID> cveIdList = vulnDetail.getCVEIDLIST().getCVEID(); 
					
					if (cveIdList != null){
						
						for (int cv = 0; cv < cveIdList.size(); cv++){
							strCveIds.append(removeBadChars(cveIdList.get(cv).getID()));
							if (cv != cveIdList.size() - 1) {
								strCveIds.append(",");
							}
						}
					}
				}
				//
				//BUG TRAQ ID concatenation
				StringBuffer strBugTraqIds = new StringBuffer();
				strBugTraqIds.setLength(0);
				if (vulnDetail.getBUGTRAQIDLIST() != null){
					List<BUGTRAQID> bugTraqList = vulnDetail.getBUGTRAQIDLIST().getBUGTRAQID(); 
					
					if (bugTraqList != null){
						
						for (int bt = 0; bt < bugTraqList.size(); bt++){
							strBugTraqIds.append(removeBadChars(bugTraqList.get(bt).getID()));
							if (bt != bugTraqList.size()-1) {
								strBugTraqIds.append(",");
							}
							
						}
					}
				}
				//
				
				String strCvssBase = vulnDetail.getCVSSSCORE().getCVSSBASE().getContent();
				String strCvssTemporal = vulnDetail.getCVSSSCORE().getCVSSTEMPORAL();				
				QID qid = vulnDetail.getQID();
				String strQid = "NULL";
				if (qid != null) {
					strQid = removeBadChars(qid.getContent());
				} 
				vulnDetailsList.append(strQid);
				vulnDetailsList.append("\t");
				vulnDetailsList.append(strTitle);
				vulnDetailsList.append("\t");
				vulnDetailsList.append(strSeverity);
				vulnDetailsList.append("\t");
				vulnDetailsList.append(strCategory);
				vulnDetailsList.append("\t");
				vulnDetailsList.append(strThreat);
				vulnDetailsList.append("\t");
				vulnDetailsList.append(strImpact);
				vulnDetailsList.append("\t");
				vulnDetailsList.append(strSolution);
				vulnDetailsList.append("\t");
				vulnDetailsList.append(strPciFlag);
				vulnDetailsList.append("\t");
				vulnDetailsList.append(strCveIds);
				vulnDetailsList.append("\t");
				vulnDetailsList.append(strBugTraqIds);
				vulnDetailsList.append("\t");
				vulnDetailsList.append(strCvssBase);
				vulnDetailsList.append("\t");
				vulnDetailsList.append(strCvssTemporal);
				vulnDetailsList.append("\t");
				vulnDetailsList.append(strLastUpdateDate);
				out.println(vulnDetailsList.toString());			
			}
			out.close();
			StringBuffer vulnerabilityGlossaryHive = new StringBuffer();
			vulnerabilityGlossaryHive.setLength(0);
			vulnerabilityGlossaryHive.append("use peaudit;\n");
			vulnerabilityGlossaryHive.append("create table IF NOT EXISTS qualys_vulnerabilityglossary (QID string,"+
					"TITLE string, SEVERITY string, CATEGORY string, THREAT string, IMPACT string, SOLUTION string, PCIFLAG string, CVE_IDS string, BUGTRAQ_IDS String, CVSS_BASE String, CVSS_TEMPORAL String,  LASTUPDATEDATE string"+
					") partitioned by (loadtime string) ROW FORMAT DELIMITED FIELDS TERMINATED BY '\\t' stored as TEXTFILE;\n");
			vulnerabilityGlossaryHive.append("LOAD DATA LOCAL INPATH './vulndetailslist.txt' INTO TABLE qualys_vulnerabilityglossary PARTITION (loadtime='"+loadTime+"');");
			try {
				PrintWriter out2 = new PrintWriter("vulnerabilityglossary.hql");
				out2.println(vulnerabilityGlossaryHive.toString());
				out2.close();
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
			
			////////////////////////
			//HostList Table
			HOSTLIST hostListObj = assetReport.getHOSTLIST();
			if (hostListObj != null) {
				StringBuffer hostListData = new StringBuffer();
				PrintWriter out = null;
				try {
					out = new PrintWriter("hostdatalist.txt");
				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

				List<HOST> listOfHosts = assetReport.getHOSTLIST().getHOST();		
				for (int hi = 0; hi < listOfHosts.size(); hi++) {
					HOST host = listOfHosts.get(hi);
					String strIp = "NULL";
					IP ip = host.getIP();
					if (ip != null ){
						strIp = removeBadChars(ip.getContent());
					} 
					String strOs = removeBadChars(host.getOPERATINGSYSTEM());
					String strTrkm = removeBadChars(host.getTRACKINGMETHOD());
					String strNetbios = removeBadChars(host.getNETBIOS());
					String strDns = removeBadChars(host.getDNS());
					String strOsCpe = removeBadChars(host.getOSCPE());
					ASSETGROUPS hostAssetGroupTagObj = host.getASSETGROUPS();
					String assetGrouphostTag = "NULL";
					if (hostAssetGroupTagObj != null) {
						List<String> hostAssetGroupTagList = host.getASSETGROUPS().getASSETGROUPTITLE();
						boolean hostTagFirst = true;
						for (int hatl = 0; hatl < hostAssetGroupTagList.size(); hatl++) {
							if(hostTagFirst){
								assetGrouphostTag = removeBadChars(hostAssetGroupTagList.get(hatl));
								hostTagFirst = false;
							} else {
								assetGrouphostTag=assetGrouphostTag+";;"+removeBadChars(hostAssetGroupTagList.get(hatl));
							}
						}
					}
					String assethostTag = "NULL";
					ASSETTAGS assetTagObj = host.getASSETTAGS();
					if (assetTagObj != null) {
						List<String> hostAssetList = host.getASSETTAGS().getASSETTAG();
						boolean assethostTagFirst = true;
						for (int hatl = 0; hatl < hostAssetList.size(); hatl++) {
							if(assethostTagFirst){
								assethostTag = removeBadChars(hostAssetList.get(hatl));
								assethostTagFirst = false;
							} else {
								assethostTag=assethostTag+";;"+removeBadChars(hostAssetList.get(hatl));
							}
						}
					}


					VULNINFOLIST hostVulnObj = host.getVULNINFOLIST();
					if (hostVulnObj != null) {
						List<VULNINFO> hostVulnsList = host.getVULNINFOLIST().getVULNINFO();
						for (int vi = 0; vi < hostVulnsList.size(); vi++) {
							hostListData.setLength(0);
							VULNINFO vuln = hostVulnsList.get(vi);
							String strFqdn = removeBadChars(vuln.getFQDN());
							String strPort = removeBadChars(vuln.getPORT());
							String strProto = removeBadChars(vuln.getPROTOCOL());
							String strSsl = removeBadChars(vuln.getSSL());
							QID qid = vuln.getQID();
							String strQid = "NULL";
							if (qid != null) {
								strQid = removeBadChars(qid.getContent());
							} 
							String strSvc = removeBadChars(vuln.getSERVICE());
							String strType = removeBadChars(vuln.getTYPE());
							String strCvsfinal = removeBadChars(vuln.getCVSSFINAL());
							String strFrstFnd = removeBadChars(vuln.getFIRSTFOUND());
							String strLstFnd = removeBadChars(vuln.getLASTFOUND());
							String strTimeFnd = removeBadChars(vuln.getTIMESFOUND());
							String strTicketNum = removeBadChars(vuln.getTICKETNUMBER());
							String strTicketState = removeBadChars(vuln.getTICKETSTATE());
							String strStatus = removeBadChars(vuln.getVULNSTATUS());
							RESULT result = vuln.getRESULT();
							String strContent = "NULL";
							if(result != null ) {
								strContent= removeBadChars(result.getContent());
							}
							hostListData.append(strIp);
							hostListData.append("\t");
							hostListData.append(strOs);
							hostListData.append("\t");
							hostListData.append(strTrkm);
							hostListData.append("\t");
							hostListData.append(strNetbios);
							hostListData.append("\t");
							hostListData.append(strDns);
							hostListData.append("\t");
							hostListData.append(strOsCpe);
							hostListData.append("\t");
							hostListData.append(assetGrouphostTag);
							hostListData.append("\t");
							hostListData.append(assethostTag);
							hostListData.append("\t");
							hostListData.append(strFqdn);
							hostListData.append("\t");
							hostListData.append(strPort);
							hostListData.append("\t");
							hostListData.append(strProto);
							hostListData.append("\t");
							hostListData.append(strSsl);
							hostListData.append("\t");
							hostListData.append(strQid);
							hostListData.append("\t");
							hostListData.append(strSvc);
							hostListData.append("\t");
							hostListData.append(strType);
							hostListData.append("\t");
							hostListData.append(strCvsfinal);
							hostListData.append("\t");
							hostListData.append(strFrstFnd);
							hostListData.append("\t");
							hostListData.append(strLstFnd);
							hostListData.append("\t");
							hostListData.append(strTimeFnd);
							hostListData.append("\t");
							hostListData.append(strTicketNum);
							hostListData.append("\t");
							hostListData.append(strTicketState);
							hostListData.append("\t");
							hostListData.append(strStatus);
							hostListData.append("\t");
							hostListData.append(strContent);
							out.println(hostListData.toString());

						}
					}
				}
				out.close();
				StringBuffer riskScorePerHostDataHive = new StringBuffer();
				riskScorePerHostDataHive.setLength(0);
				riskScorePerHostDataHive.append("use peaudit;\n");
				riskScorePerHostDataHive.append("create table IF NOT EXISTS qualys_hostdatalist (IP string,"+
						"OPERATINGSYSTEM string, TRACKINGMETHOD string," +
						"NETBIOS string, DNS string, OS_CPE string, ASSETGROUP String, ASSETTAGHost string, "+
						"FQDN String,PORT string,PROTOCOL string, "+
						"SSL string, QID string, SERVICE string,"+
						"TYPE String, CVSSFINAL string,FIRSTFOUND string,"+
						"LASTFOUND String,TIMESFOUND String,TICKETNUMBER string,"+
						"TICKETSTATE string, VULNSTATUS string, result string"+
						") partitioned by (loadtime string) ROW FORMAT DELIMITED FIELDS TERMINATED BY '\\t' stored as TEXTFILE;\n");
				riskScorePerHostDataHive.append("LOAD DATA LOCAL INPATH './hostdatalist.txt' INTO TABLE qualys_hostdatalist PARTITION (loadtime='"+loadTime+"');");
				try {
					PrintWriter out2 = new PrintWriter("hostdatalist.hql");
					out2.println(riskScorePerHostDataHive.toString());
					out2.close();
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

	}	


	public static String removeBadChars( String strToBeTrimmed)  
	{  
		String strout = "NULL";
		if (strToBeTrimmed != null) {
			strout = StringUtils.replace(strToBeTrimmed, "\n\r", " ");
			strout = StringUtils.replace(strout, "\r\n", " ");
			strout = StringUtils.replace(strout, "\n", " ");
			strout = StringUtils.replace(strout, "\r", " ");
			strout = StringUtils.replace(strout, "\t", " ");
			strout = StringUtils.replace(strout, "\b", " ");

		}
		if (!(StringUtils.isAsciiPrintable(strout))) {
			strout = Normalizer.normalize(strout, Normalizer.Form.NFD);
			strout = strout.replaceAll("[^\\x00-\\x7F]", ""); //will search and replace all non-ASCII characters
		}
		return strout;  
	}  

}
