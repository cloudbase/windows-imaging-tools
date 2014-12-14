<xsl:stylesheet version="1.0"
            xmlns="http://www.w3.org/1999/xhtml"
            xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:u="urn:schemas-microsoft-com:unattend">

  <xsl:output method="xml" indent="yes" />

  <xsl:strip-space elements="*"/>

  <xsl:param name="productKey" />
  <xsl:param name="processorArchitecture" />
  <xsl:param name="imageName" />
  <xsl:param name="versionMajor" />
  <xsl:param name="versionMinor" />
  <xsl:param name="installationType" />
  <xsl:param name="administratorPassword" />

  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match='u:unattend/u:settings/u:component[@name="Microsoft-Windows-Setup"]/u:ImageInstall/u:OSImage/u:InstallFrom/u:MetaData/u:Value'>
    <xsl:copy>
      <xsl:apply-templates select="@*"/>
      <xsl:value-of select="$imageName"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match='u:unattend/u:settings/u:component[@name="Microsoft-Windows-Shell-Setup"]/u:OOBE/u:HideOnlineAccountScreens | u:unattend/u:settings/u:component[@name="Microsoft-Windows-Shell-Setup"]/u:OOBE/u:HideLocalAccountScreen'>
      <xsl:if test="$versionMajor &gt;= 6 and $versionMinor &gt;= 2">
        <xsl:copy>
          <xsl:apply-templates select="@*|node()"/>
        </xsl:copy>
      </xsl:if>
  </xsl:template>

  <xsl:template match='u:unattend/u:settings/u:component[@name="Microsoft-Windows-Shell-Setup"]/u:UserAccounts/u:AdministratorPassword|u:unattend/u:settings/u:component[@name="Microsoft-Windows-Shell-Setup"]/u:AutoLogon/u:Password'>
    <xsl:copy>
      <xsl:element name="Value" namespace="{namespace-uri()}">
        <xsl:value-of select="$administratorPassword"/>
      </xsl:element>
      <xsl:element name="PlainText" namespace="{namespace-uri()}">true</xsl:element>
    </xsl:copy>
  </xsl:template>

  <xsl:template match='u:unattend/u:settings/u:component[@name="Microsoft-Windows-Shell-Setup"]/u:UserAccounts[not(u:LocalAccounts)]'>
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
      <xsl:if test="$installationType = 'Client'">
        <xsl:element name="LocalAccounts" namespace="{namespace-uri()}">
          <xsl:element name="LocalAccount" namespace="{namespace-uri()}">
            <xsl:attribute name="wcm:action">add</xsl:attribute>
            <xsl:element name="Description" namespace="{namespace-uri()}">Admin user</xsl:element>
            <xsl:element name="DisplayName" namespace="{namespace-uri()}">Admin</xsl:element>
            <xsl:element name="Group" namespace="{namespace-uri()}">Administrators</xsl:element>
            <xsl:element name="Name" namespace="{namespace-uri()}">Admin</xsl:element>
          </xsl:element>
        </xsl:element>
      </xsl:if>
    </xsl:copy>
  </xsl:template>

  <xsl:template match='u:unattend/u:settings/u:component[@name="Microsoft-Windows-Setup"]/u:UserData'>
    <xsl:copy>
      <xsl:apply-templates select="@*"/>
      <xsl:if test="$productKey">
        <xsl:element name="ProductKey" namespace="{namespace-uri()}">
          <xsl:element name="Key" namespace="{namespace-uri()}">
            <xsl:value-of select="$productKey"/>
          </xsl:element>
          <xsl:element name="WillShowUI" namespace="{namespace-uri()}">OnError</xsl:element>
        </xsl:element>
      </xsl:if>
      <xsl:apply-templates select="node()"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match='u:unattend/u:settings/u:component'>
    <xsl:copy>
      <xsl:apply-templates select="@*"/>
      <xsl:attribute name="processorArchitecture">
        <xsl:value-of select="$processorArchitecture"/>
      </xsl:attribute>
      <xsl:apply-templates select="node()"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match='u:unattend/u:settings[@pass="specialize"]/u:component[@name="Microsoft-Windows-Shell-Setup"]'>
    <xsl:copy>
      <xsl:apply-templates select="@*"/>
      <xsl:attribute name="processorArchitecture">
        <xsl:value-of select="$processorArchitecture"/>
      </xsl:attribute>
      <xsl:if test="$productKey">
        <xsl:element name="ProductKey" namespace="{namespace-uri()}">
            <xsl:value-of select="$productKey"/>
        </xsl:element>
      </xsl:if>
      <xsl:apply-templates select="node()"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match="comment()"/>
</xsl:stylesheet>
