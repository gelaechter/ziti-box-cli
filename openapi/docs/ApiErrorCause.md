# ApiErrorCause

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**field** | Option<**String**> |  | [optional]
**reason** | Option<**String**> |  | [optional]
**value** | Option<[**serde_json::Value**](.md)> | can be any value - string, number, boolean, array or object | [optional]
**args** | Option<[**models::ApiErrorArgs**](apiErrorArgs.md)> |  | [optional]
**cause** | Option<[**models::ApiErrorCause**](apiErrorCause.md)> |  | [optional]
**cause_message** | Option<**String**> |  | [optional]
**code** | Option<**String**> |  | [optional]
**data** | Option<[**std::collections::HashMap<String, serde_json::Value>**](serde_json::Value.md)> |  | [optional]
**message** | Option<**String**> |  | [optional]
**request_id** | Option<**String**> |  | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


