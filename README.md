# Identity and Access Management (IAM) 

This project closely resembles the AWS IAM service, but is open sourced for the community to build upon.  IAM enables your to control access to your
application level resources in a very granular manner.
Identity and Access Management (IAM) is a service that helps securely control access to resources for users. IAM is used to control who can use which resources in a very granular fashion.
  
  
# IAM ARNs
  
Following AWS IAM ARNs(Amazon Resource Naming Format) we can use something like ssrn (SmarterServices Resource Naming)
  
  ssrn:product:service:region:account:resource
  
  
  * product identifies a product. This can be something like sm for SmarterMeasures and sp for SmarterProctoring.   
  * service identifies the service. For IAM resources, this is always iam.
  * region is the region the resource resides in. For IAM resources, this is always left blank.
  * account is the account ID with no hyphens (for example, 123456789012).
  * resource is the portion that identifies the specific resource by name.
  
The ARN format can really be anything you would like as long as the policies match up.

# Policy Structure

To assign permissions to a user, group, role, or resource, you create a policy, which is a document that explicitly lists permissions. In its most basic sense, a policy lets you specify the following:

   * Actions: what actions will be allowed.  Any actions that is not explicitly allowed in the policy are denied.
   * Resources: which resources  are allowed to perform the action on.
   * Effect: what the effect will be when the user requests access—either allow or deny. Because the default is that resources are denied to users, typically we need to specify that a user is allowed access to a resource.

Policies are documents that are created using JSON. A policy consists of one or more statements, each of which describes one set of permissions. Here's an example of a simple policy.


```javascript  
{
"Statement": [
    {
      "Effect": "Allow",
      "Action": ["Read"],
      "Resource": [
        "ssrn:ss:iam::100:assessmentgroup/*/customquestions"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["Update","Delete","Create"],
      "Resource": "ssrn:ss:iam::100:assessmentgroup/1/customquestions"
    }
  ]
}
```



This policy statements allow an user with id 100 to read custom questions for any assetment group. However the user can only  perform Update, Delete and Create on assessmentgroup 1.

# Determining Whether a Request is Allowed or Denied
  
  When a request is made, the IAM service decides whether a given request should be allowed or denied. The evaluation logic follows these rules:
  
  * By default, all requests are denied.
  * An explicit allow overrides this default.
  * An explicit deny overrides any allows.
  
The order in which the policies are evaluated has no effect on the outcome of the evaluation. All policies are evaluated, and the result is always that the request is either allowed or denied.