/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
