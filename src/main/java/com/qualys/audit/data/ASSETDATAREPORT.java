//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.07.02 at 10:44:13 AM EDT 
//


package com.qualys.audit.data;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;choice>
 *         &lt;element ref="{}ERROR"/>
 *         &lt;sequence>
 *           &lt;element ref="{}HEADER"/>
 *           &lt;element ref="{}RISK_SCORE_PER_HOST" minOccurs="0"/>
 *           &lt;element ref="{}HOST_LIST" minOccurs="0"/>
 *           &lt;element ref="{}GLOSSARY" minOccurs="0"/>
 *           &lt;element ref="{}APPENDICES" minOccurs="0"/>
 *         &lt;/sequence>
 *       &lt;/choice>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "error",
    "header",
    "riskscoreperhost",
    "hostlist",
    "glossary",
    "appendices"
})
@XmlRootElement(name = "ASSET_DATA_REPORT")
public class ASSETDATAREPORT {

    @XmlElement(name = "ERROR")
    protected ERROR error;
    @XmlElement(name = "HEADER")
    protected HEADER header;
    @XmlElement(name = "RISK_SCORE_PER_HOST")
    protected RISKSCOREPERHOST riskscoreperhost;
    @XmlElement(name = "HOST_LIST")
    protected HOSTLIST hostlist;
    @XmlElement(name = "GLOSSARY")
    protected GLOSSARY glossary;
    @XmlElement(name = "APPENDICES")
    protected APPENDICES appendices;

    /**
     * Gets the value of the error property.
     * 
     * @return
     *     possible object is
     *     {@link ERROR }
     *     
     */
    public ERROR getERROR() {
        return error;
    }

    /**
     * Sets the value of the error property.
     * 
     * @param value
     *     allowed object is
     *     {@link ERROR }
     *     
     */
    public void setERROR(ERROR value) {
        this.error = value;
    }

    /**
     * Gets the value of the header property.
     * 
     * @return
     *     possible object is
     *     {@link HEADER }
     *     
     */
    public HEADER getHEADER() {
        return header;
    }

    /**
     * Sets the value of the header property.
     * 
     * @param value
     *     allowed object is
     *     {@link HEADER }
     *     
     */
    public void setHEADER(HEADER value) {
        this.header = value;
    }

    /**
     * Gets the value of the riskscoreperhost property.
     * 
     * @return
     *     possible object is
     *     {@link RISKSCOREPERHOST }
     *     
     */
    public RISKSCOREPERHOST getRISKSCOREPERHOST() {
        return riskscoreperhost;
    }

    /**
     * Sets the value of the riskscoreperhost property.
     * 
     * @param value
     *     allowed object is
     *     {@link RISKSCOREPERHOST }
     *     
     */
    public void setRISKSCOREPERHOST(RISKSCOREPERHOST value) {
        this.riskscoreperhost = value;
    }

    /**
     * Gets the value of the hostlist property.
     * 
     * @return
     *     possible object is
     *     {@link HOSTLIST }
     *     
     */
    public HOSTLIST getHOSTLIST() {
        return hostlist;
    }

    /**
     * Sets the value of the hostlist property.
     * 
     * @param value
     *     allowed object is
     *     {@link HOSTLIST }
     *     
     */
    public void setHOSTLIST(HOSTLIST value) {
        this.hostlist = value;
    }

    /**
     * Gets the value of the glossary property.
     * 
     * @return
     *     possible object is
     *     {@link GLOSSARY }
     *     
     */
    public GLOSSARY getGLOSSARY() {
        return glossary;
    }

    /**
     * Sets the value of the glossary property.
     * 
     * @param value
     *     allowed object is
     *     {@link GLOSSARY }
     *     
     */
    public void setGLOSSARY(GLOSSARY value) {
        this.glossary = value;
    }

    /**
     * Gets the value of the appendices property.
     * 
     * @return
     *     possible object is
     *     {@link APPENDICES }
     *     
     */
    public APPENDICES getAPPENDICES() {
        return appendices;
    }

    /**
     * Sets the value of the appendices property.
     * 
     * @param value
     *     allowed object is
     *     {@link APPENDICES }
     *     
     */
    public void setAPPENDICES(APPENDICES value) {
        this.appendices = value;
    }

}