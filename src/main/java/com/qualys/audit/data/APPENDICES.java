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
 *         &lt;element ref="{}NO_RESULTS" minOccurs="0"/>
 *         &lt;element ref="{}NO_VULNS" minOccurs="0"/>
 *         &lt;element ref="{}TEMPLATE_DETAILS" minOccurs="0"/>
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
    "noresults",
    "novulns",
    "templatedetails"
})
@XmlRootElement(name = "APPENDICES")
public class APPENDICES {

    @XmlElement(name = "NO_RESULTS")
    protected NORESULTS noresults;
    @XmlElement(name = "NO_VULNS")
    protected NOVULNS novulns;
    @XmlElement(name = "TEMPLATE_DETAILS")
    protected TEMPLATEDETAILS templatedetails;

    /**
     * Gets the value of the noresults property.
     * 
     * @return
     *     possible object is
     *     {@link NORESULTS }
     *     
     */
    public NORESULTS getNORESULTS() {
        return noresults;
    }

    /**
     * Sets the value of the noresults property.
     * 
     * @param value
     *     allowed object is
     *     {@link NORESULTS }
     *     
     */
    public void setNORESULTS(NORESULTS value) {
        this.noresults = value;
    }

    /**
     * Gets the value of the novulns property.
     * 
     * @return
     *     possible object is
     *     {@link NOVULNS }
     *     
     */
    public NOVULNS getNOVULNS() {
        return novulns;
    }

    /**
     * Sets the value of the novulns property.
     * 
     * @param value
     *     allowed object is
     *     {@link NOVULNS }
     *     
     */
    public void setNOVULNS(NOVULNS value) {
        this.novulns = value;
    }

    /**
     * Gets the value of the templatedetails property.
     * 
     * @return
     *     possible object is
     *     {@link TEMPLATEDETAILS }
     *     
     */
    public TEMPLATEDETAILS getTEMPLATEDETAILS() {
        return templatedetails;
    }

    /**
     * Sets the value of the templatedetails property.
     * 
     * @param value
     *     allowed object is
     *     {@link TEMPLATEDETAILS }
     *     
     */
    public void setTEMPLATEDETAILS(TEMPLATEDETAILS value) {
        this.templatedetails = value;
    }

}
