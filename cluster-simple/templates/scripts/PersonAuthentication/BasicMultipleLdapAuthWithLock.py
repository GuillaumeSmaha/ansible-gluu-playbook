from org.jboss.seam import Component
from org.jboss.seam.faces import FacesMessages
from javax.faces.context import FacesContext
from javax.faces.application import FacesMessage
from org.jboss.seam.security import Identity
from org.xdi.model.custom.script.type.auth import PersonAuthenticationType
from org.xdi.oxauth.service import UserService, AuthenticationService, AppInitializer
from org.xdi.util import StringHelper
from org.xdi.util import ArrayHelper
from org.xdi.model.ldap import GluuLdapConfiguration
from java.util import Arrays

import java


try:
    import json
except ImportError:
    import simplejson as json


class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "Basic (multi auth conf & lock account). Initialization"

        if (not configurationAttributes.containsKey("auth_configuration_file")):
            print "Basic (multi auth conf & lock account). The property auth_configuration_file is empty"
            return False

        self.invalidLoginCountAttribute = "oxCountInvalidLogin"
        if configurationAttributes.containsKey("invalid_login_count_attribute"):
            self.invalidLoginCountAttribute = configurationAttributes.get(
                "invalid_login_count_attribute").getValue2()
        else:
            print "Basic (multi auth conf & lock account). Initialization. Using default attribute"

        self.maximumInvalidLoginAttemps = 3
        if configurationAttributes.containsKey("maximum_invalid_login_attemps"):
            self.maximumInvalidLoginAttemps = StringHelper.toInteger(
                configurationAttributes.get("maximum_invalid_login_attemps").getValue2())
        else:
            print "Basic (multi auth conf & lock account). Initialization. Using default number attempts"

        authConfigurationFile = configurationAttributes.get(
            "auth_configuration_file").getValue2()
        authConfiguration = self.loadAuthConfiguration(authConfigurationFile)
        if (authConfiguration == None):
            print "Basic (multi auth conf & lock account). File with authentication configuration should be not empty"
            return False

        validationResult = self.validateAuthConfiguration(authConfiguration)
        if (not validationResult):
            return False

        ldapExtendedEntryManagers = self.createLdapExtendedEntryManagers(
            authConfiguration)
        if (ldapExtendedEntryManagers == None):
            return False

        self.ldapExtendedEntryManagers = ldapExtendedEntryManagers

        print "Basic (multi auth conf & lock account). Initialized successfully"
        return True

    def destroy(self, authConfiguration):
        print "Basic (multi auth conf & lock account). Destroy"

        result = True
        for ldapExtendedEntryManager in self.ldapExtendedEntryManagers:
            ldapConfiguration = ldapExtendedEntryManager["ldapConfiguration"]
            ldapEntryManager = ldapExtendedEntryManager["ldapEntryManager"]

            destoryResult = ldapEntryManager.destroy()
            result = result and destoryResult
            print "Basic (multi auth conf & lock account). Destroyed: " + ldapConfiguration.getConfigId() + ". Result: " + str(destoryResult)

        print "Basic (multi auth conf & lock account). Destroyed successfully"

        return result

    def getApiVersion(self):
        return 1

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            print "Basic (multi auth conf & lock account). Authenticate for step 1"

            credentials = Identity.instance().getCredentials()
            keyValue = credentials.getUsername()
            userPassword = credentials.getPassword()

            if not StringHelper.isNotEmptyString(keyValue) or not StringHelper.isNotEmptyString(userPassword):
                print "Basic (multi auth conf & lock account). Missing fields "
                faces_messages = FacesMessages.instance()
                faces_messages.clear()
                FacesContext.getCurrentInstance().getExternalContext().getFlash().setKeepMessages(True)
                faces_messages.addFromResourceBundle(
                    FacesMessage.SEVERITY_ERROR, "login.missingField")
                return False

            keyValue = keyValue.strip()

            user_status = self.getUserAttributeValue(keyValue, "gluuStatus")
            if user_status != None and user_status != "active":
                print "Basic (multi auth conf & lock account). Account locked for user '%s'" % keyValue
                faces_messages = FacesMessages.instance()
                faces_messages.clear()
                FacesContext.getCurrentInstance().getExternalContext().getFlash().setKeepMessages(True)
                faces_messages.addFromResourceBundle(
                    FacesMessage.SEVERITY_ERROR, "login.accountLocked")
                return False

            if (StringHelper.isNotEmptyString(keyValue) and StringHelper.isNotEmptyString(userPassword)):
                authenticationService = Component.getInstance(
                    AuthenticationService)

                logged_in = False
                for ldapExtendedEntryManager in self.ldapExtendedEntryManagers:
                    if logged_in:
                        break

                    ldapConfiguration = ldapExtendedEntryManager["ldapConfiguration"]
                    ldapEntryManager = ldapExtendedEntryManager["ldapEntryManager"]
                    loginAttributes = ldapExtendedEntryManager["loginAttributes"]
                    localLoginAttributes = ldapExtendedEntryManager["localLoginAttributes"]

                    print "Basic (multi auth conf & lock account). Authenticate for step 1. Using configuration: " + ldapConfiguration.getConfigId()

                    idx = 0
                    count = len(loginAttributes)
                    while (idx < count):
                        primaryKey = loginAttributes[idx]
                        localPrimaryKey = localLoginAttributes[idx]

                        loggedIn = authenticationService.authenticate(
                            ldapConfiguration, ldapEntryManager, keyValue, userPassword, primaryKey, localPrimaryKey)
                        if (loggedIn):
                            logged_in = True
                            break
                        idx += 1

                if logged_in:
                    self.setUserAttributeValue(
                        keyValue, self.invalidLoginCountAttribute, StringHelper.toString(0))

                    return True

                countInvalidLoginArributeValue = self.getUserAttributeValue(
                    keyValue, self.invalidLoginCountAttribute)
                countInvalidLogin = StringHelper.toInteger(
                    countInvalidLoginArributeValue, 0)

                if countInvalidLogin < self.maximumInvalidLoginAttemps:
                    countInvalidLogin = countInvalidLogin + 1
                    self.setUserAttributeValue(
                        keyValue, self.invalidLoginCountAttribute, StringHelper.toString(countInvalidLogin))

                if countInvalidLogin >= self.maximumInvalidLoginAttemps:
                    self.lockUser(keyValue)
                    self.setUserAttributeValue(
                        keyValue, self.invalidLoginCountAttribute, StringHelper.toString(0))

            return False
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            print "Basic (multi auth conf & lock account). Prepare for Step 1"
            return True
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 1

    def getPageForStep(self, configurationAttributes, step):
        return ""

    def logout(self, configurationAttributes, requestParameters):
        return True

    def loadAuthConfiguration(self, authConfigurationFile):
        authConfiguration = None

        # Load authentication configuration from file
        f = open(authConfigurationFile, 'r')
        try:
            authConfiguration = json.loads(f.read())
        except:
            print "Basic (multi auth conf & lock account). Load auth configuration. Failed to load authentication configuration from file:", authConfigurationFile
            return None
        finally:
            f.close()

        return authConfiguration

    def validateAuthConfiguration(self, authConfiguration):
        isValid = True

        if (not ("ldap_configuration" in authConfiguration)):
            print "Basic (multi auth conf & lock account). Validate auth configuration. There is no ldap_configuration section in configuration"
            return False

            #@JsonPropertyOrder({ "configId", "bindDN", "bindPassword", "servers", "maxConnections", "useSSL", "baseDNs", "primaryKey",
            #        "localPrimaryKey", "useAnonymousBind" })
        idx = 1
        for ldapConfiguration in authConfiguration["ldap_configuration"]:
            if (not self.containsAttributeString(ldapConfiguration, "configId")):
                print "Basic (multi auth conf & lock account). Validate auth configuration. There is no 'configId' attribute in ldap_configuration section #" + str(idx)
                return False

            configId = ldapConfiguration["configId"]

            if (not self.containsAttributeArray(ldapConfiguration, "servers")):
                print "Basic (multi auth conf & lock account). Validate auth configuration. Property 'servers' in configuration '" + configId + "' is invalid"
                return False

            if (self.containsAttributeString(ldapConfiguration, "bindDN")):
                if (not self.containsAttributeString(ldapConfiguration, "bindPassword")):
                    print "Basic (multi auth conf & lock account). Validate auth configuration. Property 'bindPassword' in configuration '" + configId + "' is invalid"
                    return False

            if (not self.containsAttributeString(ldapConfiguration, "useSSL")):
                print "Basic (multi auth conf & lock account). Validate auth configuration. Property 'useSSL' in configuration '" + configId + "' is invalid"
                return False

            if (not self.containsAttributeString(ldapConfiguration, "maxConnections")):
                print "Basic (multi auth conf & lock account). Validate auth configuration. Property 'maxConnections' in configuration '" + configId + "' is invalid"
                return False

            if (not self.containsAttributeArray(ldapConfiguration, "baseDNs")):
                print "Basic (multi auth conf & lock account). Validate auth configuration. Property 'baseDNs' in configuration '" + configId + "' is invalid"
                return False

            if (not self.containsAttributeArray(ldapConfiguration, "loginAttributes")):
                print "Basic (multi auth conf & lock account). Validate auth configuration. Property 'loginAttributes' in configuration '" + configId + "' is invalid"
                return False

            if (not self.containsAttributeArray(ldapConfiguration, "localLoginAttributes")):
                print "Basic (multi auth conf & lock account). Validate auth configuration. Property 'localLoginAttributes' in configuration '" + configId + "' is invalid"
                return False

            if (len(ldapConfiguration["loginAttributes"]) != len(ldapConfiguration["localLoginAttributes"])):
                print "Basic (multi auth conf & lock account). Validate auth configuration. The number of attributes in 'loginAttributes' and 'localLoginAttributes' isn't equal in configuration '" + configId + "'"
                return False

            idx += 1

        return True

    def createLdapExtendedEntryManagers(self, authConfiguration):
        ldapExtendedConfigurations = self.createLdapExtendedConfigurations(
            authConfiguration)

        appInitializer = Component.getInstance(AppInitializer)

        ldapExtendedEntryManagers = []
        for ldapExtendedConfiguration in ldapExtendedConfigurations:
            ldapEntryManager = appInitializer.createLdapAuthEntryManager(
                ldapExtendedConfiguration["ldapConfiguration"])
            ldapExtendedEntryManagers.append({"ldapConfiguration": ldapExtendedConfiguration["ldapConfiguration"], "loginAttributes": ldapExtendedConfiguration[
                                             "loginAttributes"], "localLoginAttributes": ldapExtendedConfiguration["localLoginAttributes"], "ldapEntryManager": ldapEntryManager})

        return ldapExtendedEntryManagers

    def createLdapExtendedConfigurations(self, authConfiguration):
        ldapExtendedConfigurations = []

        for ldapConfiguration in authConfiguration["ldap_configuration"]:
            configId = ldapConfiguration["configId"]

            servers = ldapConfiguration["servers"]

            bindDN = None
            bindPassword = None
            useAnonymousBind = True
            if (self.containsAttributeString(ldapConfiguration, "bindDN")):
                useAnonymousBind = False
                bindDN = ldapConfiguration["bindDN"]
                bindPassword = ldapConfiguration["bindPassword"]

            useSSL = ldapConfiguration["useSSL"]
            maxConnections = ldapConfiguration["maxConnections"]
            baseDNs = ldapConfiguration["baseDNs"]
            loginAttributes = ldapConfiguration["loginAttributes"]
            localLoginAttributes = ldapConfiguration["localLoginAttributes"]

            ldapConfiguration = GluuLdapConfiguration(configId, bindDN, bindPassword, Arrays.asList(servers),
                                                      maxConnections, useSSL, Arrays.asList(
                                                          baseDNs),
                                                      loginAttributes[0], localLoginAttributes[0], useAnonymousBind)
            ldapExtendedConfigurations.append(
                {"ldapConfiguration": ldapConfiguration, "loginAttributes": loginAttributes, "localLoginAttributes": localLoginAttributes})

        return ldapExtendedConfigurations

    def containsAttributeString(self, dictionary, attribute):
        return ((attribute in dictionary) and StringHelper.isNotEmptyString(dictionary[attribute]))

    def containsAttributeArray(self, dictionary, attribute):
        return ((attribute in dictionary) and (len(dictionary[attribute]) > 0))

    def getUserAttributeValue(self, user_name, attribute_name):
        if StringHelper.isEmpty(user_name):
            return None

        userService = UserService.instance()

        find_user_by_uid = userService.getUser(user_name, attribute_name)
        if find_user_by_uid == None:
            return None

        custom_attribute_value = userService.getCustomAttribute(
            find_user_by_uid, attribute_name)
        if custom_attribute_value == None:
            return None

        attribute_value = custom_attribute_value.getValue()

        print "Basic (multi auth conf & lock account). Get user attribute. User's '%s' attribute '%s' value is '%s'" % (user_name, attribute_name, attribute_value)

        return attribute_value

    def setUserAttributeValue(self, user_name, attribute_name, attribute_value):
        if StringHelper.isEmpty(user_name):
            return None

        userService = UserService.instance()

        find_user_by_uid = userService.getUser(user_name)
        if find_user_by_uid == None:
            return None

        userService.setCustomAttribute(
            find_user_by_uid, attribute_name, attribute_value)
        updated_user = userService.updateUser(find_user_by_uid)

        print "Basic (multi auth conf & lock account). Set user attribute. User's '%s' attribute '%s' value is '%s'" % (user_name, attribute_name, attribute_value)

        return updated_user

    def lockUser(self, user_name):
        if StringHelper.isEmpty(user_name):
            return None

        userService = UserService.instance()

        find_user_by_uid = userService.getUser(user_name)
        if (find_user_by_uid == None):
            return None

        status_attribute_value = userService.getCustomAttribute(
            find_user_by_uid, "gluuStatus")
        if status_attribute_value != None:
            user_status = status_attribute_value.getValue()
            if StringHelper.equals(user_status, "inactive"):
                print "Basic (multi auth conf & lock account). Lock user. User '%s' locked already" % user_name
                return

        userService.setCustomAttribute(
            find_user_by_uid, "gluuStatus", "inactive")
        updated_user = userService.updateUser(find_user_by_uid)

        print "Basic (multi auth conf & lock account). Lock user. User '%s' locked" % user_name
