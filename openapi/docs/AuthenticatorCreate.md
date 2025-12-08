# AuthenticatorCreate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**cert_pem** | Option<**String**> | The client certificate the identity will login with. Used only for method='cert' | [optional]
**identity_id** | **String** | The id of an existing identity that will be assigned this authenticator | 
**method** | **String** | The type of authenticator to create; which will dictate which properties on this object are required. | 
**password** | Option<**String**> | The password the identity will login with. Used only for method='updb' | [optional]
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**username** | Option<**String**> | The username that the identity will login with. Used only for method='updb' | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


