import Foundation
import Store

/// MS-SAMR opnums this service implements (a subset of §3.1.4). Values match the IDL.
enum SAMROpnum {
    static let connect                  : UInt16 = 0
    static let closeHandle              : UInt16 = 1
    static let lookupDomainInSamServer  : UInt16 = 5
    static let enumerateDomains         : UInt16 = 6
    static let openDomain               : UInt16 = 7
    static let queryInformationDomain   : UInt16 = 8
    static let enumerateGroups          : UInt16 = 11
    static let createUserInDomain       : UInt16 = 12
    static let enumerateUsers           : UInt16 = 13
    static let enumerateAliases         : UInt16 = 15
    static let getAliasMembership       : UInt16 = 16
    static let lookupNamesInDomain      : UInt16 = 17
    static let lookupIdsInDomain        : UInt16 = 18
    static let openGroup                : UInt16 = 19
    static let queryInformationGroup    : UInt16 = 20
    static let getMembersInGroup        : UInt16 = 25
    static let openAlias                : UInt16 = 27
    static let queryInformationAlias    : UInt16 = 28
    static let getMembersInAlias        : UInt16 = 33
    static let openUser                 : UInt16 = 34
    static let deleteUser               : UInt16 = 35
    static let queryInformationUser     : UInt16 = 36
    static let setInformationUser       : UInt16 = 37
    static let changePasswordUser       : UInt16 = 38
    static let getGroupsForUser         : UInt16 = 39
    static let getUserDomainPasswordInfo: UInt16 = 44
    static let getDomainPasswordInformation: UInt16 = 56
    static let queryInformationDomain2  : UInt16 = 46
    static let queryInformationUser2    : UInt16 = 47
    static let createUser2InDomain      : UInt16 = 50
    static let unicodeChangePasswordUser2: UInt16 = 55
    static let connect2                 : UInt16 = 57
    static let setInformationUser2      : UInt16 = 58
    static let connect4                 : UInt16 = 62
    static let connect5                 : UInt16 = 64
    static let ridToSid                 : UInt16 = 65
    static let validatePassword         : UInt16 = 67
}

/// Access-mask values (MS-SAMR §2.2.1). We grant loosely: admins get what they ask for.
enum SAMRAccess {
    static let maximumAllowed: UInt32 = 0x0200_0000
    static let userAllAccess:  UInt32 = 0x000F_07FF
    static let groupAllAccess: UInt32 = 0x000F_001F
    static let aliasAllAccess: UInt32 = 0x000F_001F
    static let domainAllAccess: UInt32 = 0x000F_07FF
    static let serverAllAccess: UInt32 = 0x000F_003F
}

/// `SamrCreateUser2InDomain.AccountType` values: the account-type USER_* codes of MS-SAMR
/// §2.2.1.12 (ACB flags, not `userAccountControl` UF bits; see `UserAccountControl.fromACB`).
enum SAMRAccountType {
    static let normalAccount:            UInt32 = ACB.normal            // USER_NORMAL_ACCOUNT 0x10
    static let workstationTrustAccount:  UInt32 = ACB.workstationTrust  // USER_WORKSTATION_TRUST_ACCOUNT 0x80
    static let serverTrustAccount:       UInt32 = ACB.serverTrust       // USER_SERVER_TRUST_ACCOUNT 0x100
    static let interdomainTrustAccount:  UInt32 = ACB.domainTrust       // USER_INTERDOMAIN_TRUST_ACCOUNT 0x40
    static let temporaryDuplicate:       UInt32 = ACB.tempDuplicate     // USER_TEMP_DUPLICATE_ACCOUNT 0x8
}

/// SID_NAME_USE (MS-SAMR §2.2.2.3), returned by the lookup calls.
enum SIDNameUse {
    static let user:      UInt32 = 1
    static let group:     UInt32 = 2
    static let domain:    UInt32 = 3
    static let alias:     UInt32 = 4
    static let wellKnown: UInt32 = 5
    static let unknown:   UInt32 = 8
    static let computer:  UInt32 = 9
}

/// USER_ALL_* WhichFields bits (MS-SAMR §2.2.1.8), reported for a queried `SAMPR_USER_ALL_INFORMATION`.
enum UserAllFields {
    static let userName:            UInt32 = 0x0000_0001
    static let userId:              UInt32 = 0x0000_0004
    static let primaryGroupId:      UInt32 = 0x0000_0008
    static let passwordLastSet:     UInt32 = 0x0004_0000
    static let accountExpires:      UInt32 = 0x0008_0000
    static let userAccountControl:  UInt32 = 0x0010_0000
}
