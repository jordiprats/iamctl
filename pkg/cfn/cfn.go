package cfn

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jordiprats/iamctl/pkg/policy"
	"gopkg.in/yaml.v3"
)

// Template represents a CloudFormation template with only the fields we need.
type Template struct {
	Resources map[string]Resource `yaml:"Resources"`
}

// Resource represents a CloudFormation resource.
type Resource struct {
	Type       string    `yaml:"Type"`
	Properties yaml.Node `yaml:"Properties"`
}

// IAMRoleProperties holds the relevant properties of an AWS::IAM::Role resource.
type IAMRoleProperties struct {
	ManagedPolicyArns     []string
	ManagedPolicyArnsRaw  []interface{}                    // unresolved intrinsic entries
	InlinePolicies        map[string]policy.PolicyDocument // policy name -> document
	PermissionBoundary    string                           // resolved ARN or empty
	PermissionBoundaryRaw interface{}                      // raw intrinsic value when not a string
}

// IAMRole is a named IAM role extracted from a CloudFormation template.
type IAMRole struct {
	LogicalID  string
	Properties IAMRoleProperties
}

// IAMPolicyResource represents an AWS::IAM::Policy or AWS::IAM::ManagedPolicy extracted from a template.
type IAMPolicyResource struct {
	LogicalID      string
	Type           string // "AWS::IAM::Policy" or "AWS::IAM::ManagedPolicy"
	PolicyDocument policy.PolicyDocument
}

// ParseTemplate reads and parses a CloudFormation YAML/JSON template.
func ParseTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading template: %w", err)
	}

	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}
	return &tmpl, nil
}

// ExtractIAMRoles finds all AWS::IAM::Role resources in the template.
func ExtractIAMRoles(tmpl *Template) ([]IAMRole, error) {
	var roles []IAMRole
	for logicalID, res := range tmpl.Resources {
		if res.Type != "AWS::IAM::Role" {
			continue
		}

		props, err := parseRoleProperties(&res.Properties)
		if err != nil {
			return nil, fmt.Errorf("parsing role %q: %w", logicalID, err)
		}

		roles = append(roles, IAMRole{
			LogicalID:  logicalID,
			Properties: *props,
		})
	}
	return roles, nil
}

// parseRoleProperties extracts managed policy ARNs, inline policies, and permission boundary
// from the raw YAML node of an IAM role's Properties.
func parseRoleProperties(node *yaml.Node) (*IAMRoleProperties, error) {
	if node == nil || node.Kind == 0 {
		return &IAMRoleProperties{}, nil
	}

	// Decode into a generic map so we can handle intrinsic functions
	var raw map[string]interface{}
	if err := node.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding properties: %w", err)
	}

	props := &IAMRoleProperties{
		InlinePolicies: make(map[string]policy.PolicyDocument),
	}

	// Extract ManagedPolicyArns
	if arns, ok := raw["ManagedPolicyArns"]; ok {
		if arnList, ok := arns.([]interface{}); ok {
			for _, v := range arnList {
				if s, ok := v.(string); ok {
					props.ManagedPolicyArns = append(props.ManagedPolicyArns, s)
				} else {
					// Store intrinsic function entries for later resolution
					props.ManagedPolicyArnsRaw = append(props.ManagedPolicyArnsRaw, v)
				}
			}
		}
	}

	// Extract PermissionsBoundary
	if pb, ok := raw["PermissionsBoundary"]; ok {
		if s, ok := pb.(string); ok {
			props.PermissionBoundary = s
		} else {
			// Store raw intrinsic function value for later resolution
			props.PermissionBoundaryRaw = pb
		}
	}

	// Extract inline Policies
	if policies, ok := raw["Policies"]; ok {
		if policyList, ok := policies.([]interface{}); ok {
			for _, p := range policyList {
				pMap, ok := p.(map[string]interface{})
				if !ok {
					continue
				}
				name, _ := pMap["PolicyName"].(string)
				if name == "" {
					name = "unnamed"
				}
				docRaw, ok := pMap["PolicyDocument"]
				if !ok {
					continue
				}
				// Marshal to JSON then unmarshal to PolicyDocument
				// This handles the type conversions from YAML's generic types
				jsonBytes, err := json.Marshal(docRaw)
				if err != nil {
					continue
				}
				var doc policy.PolicyDocument
				if err := json.Unmarshal(jsonBytes, &doc); err != nil {
					continue
				}
				props.InlinePolicies[name] = doc
			}
		}
	}

	return props, nil
}

// ExtractIAMPolicies finds all AWS::IAM::Policy and AWS::IAM::ManagedPolicy resources in the template.
func ExtractIAMPolicies(tmpl *Template) ([]IAMPolicyResource, error) {
	var policies []IAMPolicyResource
	for logicalID, res := range tmpl.Resources {
		if res.Type != "AWS::IAM::Policy" && res.Type != "AWS::IAM::ManagedPolicy" {
			continue
		}

		doc, err := parsePolicyResource(&res.Properties)
		if err != nil {
			return nil, fmt.Errorf("parsing policy %q: %w", logicalID, err)
		}
		if doc == nil {
			continue
		}

		policies = append(policies, IAMPolicyResource{
			LogicalID:      logicalID,
			Type:           res.Type,
			PolicyDocument: *doc,
		})
	}
	return policies, nil
}

// ResolveIntrinsic attempts to resolve a CloudFormation intrinsic function value
// (such as Fn::Join, Ref, Fn::Sub) using the provided variable map.
// The vars map should contain pseudo-parameter values like "AWS::AccountId".
func ResolveIntrinsic(value interface{}, vars map[string]string) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case map[string]interface{}:
		if joinArgs, ok := v["Fn::Join"]; ok {
			args, ok := joinArgs.([]interface{})
			if !ok || len(args) != 2 {
				return "", fmt.Errorf("Fn::Join requires a 2-element array")
			}
			sep, ok := args[0].(string)
			if !ok {
				return "", fmt.Errorf("Fn::Join separator must be a string")
			}
			parts, ok := args[1].([]interface{})
			if !ok {
				return "", fmt.Errorf("Fn::Join values must be an array")
			}
			var resolved []string
			for _, p := range parts {
				s, err := ResolveIntrinsic(p, vars)
				if err != nil {
					return "", err
				}
				resolved = append(resolved, s)
			}
			return strings.Join(resolved, sep), nil
		}
		if ref, ok := v["Ref"]; ok {
			refName, ok := ref.(string)
			if !ok {
				return "", fmt.Errorf("Ref value must be a string")
			}
			if val, ok := vars[refName]; ok {
				return val, nil
			}
			return "", fmt.Errorf("unresolved Ref: %s", refName)
		}
		if sub, ok := v["Fn::Sub"]; ok {
			subStr, ok := sub.(string)
			if !ok {
				return "", fmt.Errorf("Fn::Sub value must be a string")
			}
			result := subStr
			for k, val := range vars {
				result = strings.ReplaceAll(result, "${"+k+"}", val)
			}
			return result, nil
		}
		return "", fmt.Errorf("unsupported intrinsic function")
	default:
		return "", fmt.Errorf("cannot resolve value of type %T", value)
	}
}

// parsePolicyResource extracts the PolicyDocument from an AWS::IAM::Policy or AWS::IAM::ManagedPolicy.
func parsePolicyResource(node *yaml.Node) (*policy.PolicyDocument, error) {
	if node == nil || node.Kind == 0 {
		return nil, nil
	}

	var raw map[string]interface{}
	if err := node.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding properties: %w", err)
	}

	docRaw, ok := raw["PolicyDocument"]
	if !ok {
		return nil, nil
	}

	jsonBytes, err := json.Marshal(docRaw)
	if err != nil {
		return nil, fmt.Errorf("marshalling policy document: %w", err)
	}

	var doc policy.PolicyDocument
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		return nil, fmt.Errorf("parsing policy document: %w", err)
	}

	return &doc, nil
}
