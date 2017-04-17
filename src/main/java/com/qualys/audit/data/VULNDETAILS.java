//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.07.02 at 10:44:13 AM EDT 
//
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

package com.qualys.audit.data;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlID;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{}QID"/>
 *         &lt;element ref="{}TITLE"/>
 *         &lt;element ref="{}SEVERITY"/>
 *         &lt;element ref="{}CATEGORY"/>
 *         &lt;element ref="{}CUSTOMIZED" minOccurs="0"/>
 *         &lt;element ref="{}THREAT"/>
 *         &lt;element ref="{}THREAT_COMMENT" minOccurs="0"/>
 *         &lt;element ref="{}IMPACT"/>
 *         &lt;element ref="{}IMPACT_COMMENT" minOccurs="0"/>
 *         &lt;element ref="{}SOLUTION"/>
 *         &lt;element ref="{}SOLUTION_COMMENT" minOccurs="0"/>
 *         &lt;element ref="{}COMPLIANCE" minOccurs="0"/>
 *         &lt;element ref="{}CORRELATION" minOccurs="0"/>
 *         &lt;element ref="{}PCI_FLAG"/>
 *         &lt;element ref="{}LAST_UPDATE" minOccurs="0"/>
 *         &lt;element ref="{}CVSS_SCORE" minOccurs="0"/>
 *         &lt;element ref="{}VENDOR_REFERENCE_LIST" minOccurs="0"/>
 *         &lt;element ref="{}CVE_ID_LIST" minOccurs="0"/>
 *         &lt;element ref="{}BUGTRAQ_ID_LIST" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="id" use="required" type="{http://www.w3.org/2001/XMLSchema}ID" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "qid",
    "title",
    "severity",
    "category",
    "customized",
    "threat",
    "threatcomment",
    "impact",
    "impactcomment",
    "solution",
    "solutioncomment",
    "compliance",
    "correlation",
    "pciflag",
    "lastupdate",
    "cvssscore",
    "vendorreferencelist",
    "cveidlist",
    "bugtraqidlist"
})
@XmlRootElement(name = "VULN_DETAILS")
public class VULNDETAILS {

    @XmlElement(name = "QID", required = true)
    protected QID qid;
    @XmlElement(name = "TITLE", required = true)
    protected String title;
    @XmlElement(name = "SEVERITY", required = true)
    protected String severity;
    @XmlElement(name = "CATEGORY", required = true)
    protected String category;
    @XmlElement(name = "CUSTOMIZED")
    protected CUSTOMIZED customized;
    @XmlElement(name = "THREAT", required = true)
    protected String threat;
    @XmlElement(name = "THREAT_COMMENT")
    protected String threatcomment;
    @XmlElement(name = "IMPACT", required = true)
    protected String impact;
    @XmlElement(name = "IMPACT_COMMENT")
    protected String impactcomment;
    @XmlElement(name = "SOLUTION", required = true)
    protected String solution;
    @XmlElement(name = "SOLUTION_COMMENT")
    protected String solutioncomment;
    @XmlElement(name = "COMPLIANCE")
    protected COMPLIANCE compliance;
    @XmlElement(name = "CORRELATION")
    protected CORRELATION correlation;
    @XmlElement(name = "PCI_FLAG", required = true)
    protected String pciflag;
    @XmlElement(name = "LAST_UPDATE")
    protected String lastupdate;
    @XmlElement(name = "CVSS_SCORE")
    protected CVSSSCORE cvssscore;
    @XmlElement(name = "VENDOR_REFERENCE_LIST")
    protected VENDORREFERENCELIST vendorreferencelist;
    @XmlElement(name = "CVE_ID_LIST")
    protected CVEIDLIST cveidlist;
    @XmlElement(name = "BUGTRAQ_ID_LIST")
    protected BUGTRAQIDLIST bugtraqidlist;
    @XmlAttribute(name = "id", required = true)
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlID
    @XmlSchemaType(name = "ID")
    protected String id;

    /**
     * Gets the value of the qid property.
     * 
     * @return
     *     possible object is
     *     {@link QID }
     *     
     */
    public QID getQID() {
        return qid;
    }

    /**
     * Sets the value of the qid property.
     * 
     * @param value
     *     allowed object is
     *     {@link QID }
     *     
     */
    public void setQID(QID value) {
        this.qid = value;
    }

    /**
     * Gets the value of the title property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTITLE() {
        return title;
    }

    /**
     * Sets the value of the title property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTITLE(String value) {
        this.title = value;
    }

    /**
     * Gets the value of the severity property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSEVERITY() {
        return severity;
    }

    /**
     * Sets the value of the severity property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSEVERITY(String value) {
        this.severity = value;
    }

    /**
     * Gets the value of the category property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCATEGORY() {
        return category;
    }

    /**
     * Sets the value of the category property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCATEGORY(String value) {
        this.category = value;
    }

    /**
     * Gets the value of the customized property.
     * 
     * @return
     *     possible object is
     *     {@link CUSTOMIZED }
     *     
     */
    public CUSTOMIZED getCUSTOMIZED() {
        return customized;
    }

    /**
     * Sets the value of the customized property.
     * 
     * @param value
     *     allowed object is
     *     {@link CUSTOMIZED }
     *     
     */
    public void setCUSTOMIZED(CUSTOMIZED value) {
        this.customized = value;
    }

    /**
     * Gets the value of the threat property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTHREAT() {
        return threat;
    }

    /**
     * Sets the value of the threat property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTHREAT(String value) {
        this.threat = value;
    }

    /**
     * Gets the value of the threatcomment property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTHREATCOMMENT() {
        return threatcomment;
    }

    /**
     * Sets the value of the threatcomment property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTHREATCOMMENT(String value) {
        this.threatcomment = value;
    }

    /**
     * Gets the value of the impact property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getIMPACT() {
        return impact;
    }

    /**
     * Sets the value of the impact property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setIMPACT(String value) {
        this.impact = value;
    }

    /**
     * Gets the value of the impactcomment property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getIMPACTCOMMENT() {
        return impactcomment;
    }

    /**
     * Sets the value of the impactcomment property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setIMPACTCOMMENT(String value) {
        this.impactcomment = value;
    }

    /**
     * Gets the value of the solution property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSOLUTION() {
        return solution;
    }

    /**
     * Sets the value of the solution property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSOLUTION(String value) {
        this.solution = value;
    }

    /**
     * Gets the value of the solutioncomment property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSOLUTIONCOMMENT() {
        return solutioncomment;
    }

    /**
     * Sets the value of the solutioncomment property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSOLUTIONCOMMENT(String value) {
        this.solutioncomment = value;
    }

    /**
     * Gets the value of the compliance property.
     * 
     * @return
     *     possible object is
     *     {@link COMPLIANCE }
     *     
     */
    public COMPLIANCE getCOMPLIANCE() {
        return compliance;
    }

    /**
     * Sets the value of the compliance property.
     * 
     * @param value
     *     allowed object is
     *     {@link COMPLIANCE }
     *     
     */
    public void setCOMPLIANCE(COMPLIANCE value) {
        this.compliance = value;
    }

    /**
     * Gets the value of the correlation property.
     * 
     * @return
     *     possible object is
     *     {@link CORRELATION }
     *     
     */
    public CORRELATION getCORRELATION() {
        return correlation;
    }

    /**
     * Sets the value of the correlation property.
     * 
     * @param value
     *     allowed object is
     *     {@link CORRELATION }
     *     
     */
    public void setCORRELATION(CORRELATION value) {
        this.correlation = value;
    }

    /**
     * Gets the value of the pciflag property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPCIFLAG() {
        return pciflag;
    }

    /**
     * Sets the value of the pciflag property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPCIFLAG(String value) {
        this.pciflag = value;
    }

    /**
     * Gets the value of the lastupdate property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLASTUPDATE() {
        return lastupdate;
    }

    /**
     * Sets the value of the lastupdate property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLASTUPDATE(String value) {
        this.lastupdate = value;
    }

    /**
     * Gets the value of the cvssscore property.
     * 
     * @return
     *     possible object is
     *     {@link CVSSSCORE }
     *     
     */
    public CVSSSCORE getCVSSSCORE() {
        return cvssscore;
    }

    /**
     * Sets the value of the cvssscore property.
     * 
     * @param value
     *     allowed object is
     *     {@link CVSSSCORE }
     *     
     */
    public void setCVSSSCORE(CVSSSCORE value) {
        this.cvssscore = value;
    }

    /**
     * Gets the value of the vendorreferencelist property.
     * 
     * @return
     *     possible object is
     *     {@link VENDORREFERENCELIST }
     *     
     */
    public VENDORREFERENCELIST getVENDORREFERENCELIST() {
        return vendorreferencelist;
    }

    /**
     * Sets the value of the vendorreferencelist property.
     * 
     * @param value
     *     allowed object is
     *     {@link VENDORREFERENCELIST }
     *     
     */
    public void setVENDORREFERENCELIST(VENDORREFERENCELIST value) {
        this.vendorreferencelist = value;
    }

    /**
     * Gets the value of the cveidlist property.
     * 
     * @return
     *     possible object is
     *     {@link CVEIDLIST }
     *     
     */
    public CVEIDLIST getCVEIDLIST() {
        return cveidlist;
    }

    /**
     * Sets the value of the cveidlist property.
     * 
     * @param value
     *     allowed object is
     *     {@link CVEIDLIST }
     *     
     */
    public void setCVEIDLIST(CVEIDLIST value) {
        this.cveidlist = value;
    }

    /**
     * Gets the value of the bugtraqidlist property.
     * 
     * @return
     *     possible object is
     *     {@link BUGTRAQIDLIST }
     *     
     */
    public BUGTRAQIDLIST getBUGTRAQIDLIST() {
        return bugtraqidlist;
    }

    /**
     * Sets the value of the bugtraqidlist property.
     * 
     * @param value
     *     allowed object is
     *     {@link BUGTRAQIDLIST }
     *     
     */
    public void setBUGTRAQIDLIST(BUGTRAQIDLIST value) {
        this.bugtraqidlist = value;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setId(String value) {
        this.id = value;
    }

}
