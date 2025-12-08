# \DatabaseApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**check_data_integrity**](DatabaseApi.md#check_data_integrity) | **POST** /database/check-data-integrity | Starts a data integrity scan on the datastore
[**create_database_snapshot**](DatabaseApi.md#create_database_snapshot) | **POST** /database/snapshot | Create a new database snapshot
[**data_integrity_results**](DatabaseApi.md#data_integrity_results) | **GET** /database/data-integrity-results | Returns any results found from in-progress integrity checks
[**fix_data_integrity**](DatabaseApi.md#fix_data_integrity) | **POST** /database/fix-data-integrity | Runs a data integrity scan on the datastore, attempts to fix any issues it can and returns any found issues



## check_data_integrity

> models::Empty check_data_integrity()
Starts a data integrity scan on the datastore

Starts a data integrity scan on the datastore. Requires admin access. Only once instance may run at a time, including runs of fixDataIntegrity.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## create_database_snapshot

> models::Empty create_database_snapshot()
Create a new database snapshot

Create a new database snapshot. Requires admin access.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## data_integrity_results

> models::DataIntegrityCheckResultEnvelope data_integrity_results()
Returns any results found from in-progress integrity checks

Returns any results found from in-progress integrity checks. Requires admin access.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::DataIntegrityCheckResultEnvelope**](dataIntegrityCheckResultEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## fix_data_integrity

> models::Empty fix_data_integrity()
Runs a data integrity scan on the datastore, attempts to fix any issues it can and returns any found issues

Runs a data integrity scan on the datastore, attempts to fix any issues it can, and returns any found issues. Requires admin access. Only once instance may run at a time, including runs of checkDataIntegrity.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

