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
 *       &lt;sequence>
 *         &lt;element ref="{}VULN_DETAILS_LIST"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "vulndetailslist"
})
@XmlRootElement(name = "GLOSSARY")
public class GLOSSARY {

    @XmlElement(name = "VULN_DETAILS_LIST", required = true)
    protected VULNDETAILSLIST vulndetailslist;

    /**
     * Gets the value of the vulndetailslist property.
     * 
     * @return
     *     possible object is
     *     {@link VULNDETAILSLIST }
     *     
     */
    public VULNDETAILSLIST getVULNDETAILSLIST() {
        return vulndetailslist;
    }

    /**
     * Sets the value of the vulndetailslist property.
     * 
     * @param value
     *     allowed object is
     *     {@link VULNDETAILSLIST }
     *     
     */
    public void setVULNDETAILSLIST(VULNDETAILSLIST value) {
        this.vulndetailslist = value;
    }

}
