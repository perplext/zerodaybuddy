# HackerOne API Limitations for Individual Hackers

## The Issue

ZeroDayBuddy is currently designed to work with **organization accounts** on bug bounty platforms, not individual hacker accounts. This is why you're getting authentication errors even with a valid API token.

## Key Differences

### Organization Accounts
- Full API access to manage programs
- Can list all their programs via `/v1/programs`
- Can create projects and manage scope
- Designed for companies running bug bounty programs

### Individual Hacker Accounts
- Limited API access
- Cannot list programs via the standard API
- API tokens have restricted permissions
- Designed for security researchers participating in programs

## Your API Token

The tokens you've been using (e.g., `7/MWa3OclQHCK97QEtv5rSbjxjrNEe4DRfiOE6T8c1Y=`) appear to be in the correct format for HackerOne. The issue is not the token format, but rather that individual hacker accounts don't have access to the endpoints ZeroDayBuddy is trying to use.

## Workarounds

### Option 1: Manual Project Creation
Since you can't list programs via API, you could manually create projects in the database:

```sql
-- Example SQL to manually add a project
INSERT INTO projects (
    id, name, handle, platform, status, 
    start_date, scope_json, description,
    created_at, updated_at
) VALUES (
    'manual-hackerone-project',
    'Project Name',
    'project-handle',
    'hackerone',
    'active',
    datetime('now'),
    '{"in_scope":[{"target":"*.example.com","type":"domain"}],"out_of_scope":[]}',
    'Manually created project',
    datetime('now'),
    datetime('now')
);
```

### Option 2: Use Bugcrowd Instead
Bugcrowd uses a different authentication method (session cookies) which might work differently for individual researchers.

### Option 3: Organization Partnership
If you're working with a company that has a HackerOne organization account, they could provide you with organization-level API access.

## Future Improvements

To properly support individual hackers, ZeroDayBuddy would need:

1. **Different API Endpoints**: Use hacker-specific endpoints (if available)
2. **Manual Program Import**: Allow hackers to manually input program details
3. **Web Scraping Option**: As a fallback when API access is limited
4. **Mixed Mode**: Support both organization and hacker workflows

## Alternative Tools

For individual hackers, consider:
- Using ZeroDayBuddy's reconnaissance features on manually created projects
- Browser extensions that can extract program data
- Scripts that parse HackerOne's web interface
- Community tools designed specifically for hackers

## Conclusion

The authentication error you're experiencing is not due to an incorrect token, but rather a fundamental limitation in how ZeroDayBuddy is designed. It expects organization-level API access that individual hacker accounts don't have.

To use ZeroDayBuddy effectively as an individual hacker, you would need to:
1. Manually create projects in the database
2. Focus on using the reconnaissance and scanning features
3. Skip the platform integration features