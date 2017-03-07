package com.qualys.audit;

import java.io.File;
import java.io.StringReader;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;

import com.qualys.audit.data.*;



public class XMLParser {

		ASSETDATAREPORT assetDataReport = null;


		public ASSETDATAREPORT getAssetDataReport() {
			return assetDataReport;
		}
		public  void setAssetDataReport(ASSETDATAREPORT assetDataReport) {
			this.assetDataReport = assetDataReport;
		}
		
		
		public ASSETDATAREPORT readXML(String strXMLFilePath) {
			 ASSETDATAREPORT assetReport = null;
			File file = null;
			try {
				file = new File(strXMLFilePath); //$NON-NLS-1$
				JAXBContext jaxbContext = JAXBContext
						.newInstance(ASSETDATAREPORT.class);
				Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
				assetReport = jaxbUnmarshaller.unmarshal(new StreamSource(file),ASSETDATAREPORT.class).getValue();
				if (assetReport != null) {
					this.setAssetDataReport(assetReport);
				}

				// strResult = wasProfile.getIndex() + wasProfile.getProfileName()+
				// wasProfile.getUserId() ;
			} catch (JAXBException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}finally{
				file = null;
			}

			return this.assetDataReport;
		}
		
		
		public  ASSETDATAREPORT readXMLString(String strXML) {
			ASSETDATAREPORT assetReport = null;
			File file = null;
			try {
				StringReader xmlreader = new StringReader(strXML);
				//file = new File(strXML); //$NON-NLS-1$
				JAXBContext jaxbContext = JAXBContext
						.newInstance(ASSETDATAREPORT.class);
				Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
				assetReport = (ASSETDATAREPORT) ((JAXBElement<?>) jaxbUnmarshaller.unmarshal(xmlreader)).getValue();
				if (assetReport != null) {
					this.setAssetDataReport(assetReport);
				}

				// strResult = wasProfile.getIndex() + wasProfile.getProfileName()+
				// wasProfile.getUserId() ;
			} catch (JAXBException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}finally{
				file = null;
			}

			return this.assetDataReport;
		}
}
