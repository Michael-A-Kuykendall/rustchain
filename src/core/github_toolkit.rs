// GitHub Integration Toolkit Implementation
use crate::core::error::{RustChainError, ToolError};
use crate::core::tools::{Tool, ToolCapability, ToolResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// GitHub API client for repository operations, issue management, and code analysis
#[derive(Debug)]
pub struct GitHubClient {
    token: String,
    base_url: String,
    client: reqwest::Client,
}

impl GitHubClient {
    pub fn new(token: String) -> Self {
        Self {
            token,
            base_url: "https://api.github.com".to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }

    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    async fn make_request<T>(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<T, RustChainError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut request = self
            .client
            .request(method, url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "RustChain-GitHub-Toolkit/1.0");

        if let Some(body) = body {
            request = request.json(body);
        }

        let response = request.send().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "github_client".to_string(),
                reason: format!("Failed to send request: {}", e),
            })
        })?;

        if !response.status().is_success() {
            let status = response.status();
            // Bounded read: limit error body to 10KB
            let error_bytes = response
                .bytes()
                .await
                .map(|b| b.slice(..b.len().min(10 * 1024)))
                .unwrap_or_default();
            let error_text = String::from_utf8_lossy(&error_bytes);
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "github_client".to_string(),
                reason: format!("GitHub API error {}: {}", status, error_text),
            }));
        }

        let result: T = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "github_client".to_string(),
                reason: format!("Failed to parse response: {}", e),
            })
        })?;

        Ok(result)
    }

    // Repository operations
    pub async fn get_repository(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Repository, RustChainError> {
        let url = format!("{}/repos/{}/{}", self.base_url, owner, repo);
        debug!("Getting repository: {}/{}", owner, repo);

        let repository = self.make_request(reqwest::Method::GET, &url, None).await?;
        info!("Successfully retrieved repository: {}/{}", owner, repo);
        Ok(repository)
    }

    pub async fn list_repositories(
        &self,
        owner: &str,
        per_page: Option<u32>,
    ) -> Result<Vec<Repository>, RustChainError> {
        let per_page = per_page.unwrap_or(30).min(100);
        let url = format!(
            "{}/users/{}/repos?per_page={}",
            self.base_url, owner, per_page
        );
        debug!("Listing repositories for user: {}", owner);

        let repositories = self.make_request(reqwest::Method::GET, &url, None).await?;
        info!(
            "Successfully listed {} repositories for user: {}",
            if let Ok(repos) = serde_json::from_value::<Vec<Repository>>(
                serde_json::to_value(&repositories).unwrap_or_default()
            ) {
                repos.len()
            } else {
                0
            },
            owner
        );
        Ok(repositories)
    }

    pub async fn create_repository(
        &self,
        request: CreateRepositoryRequest,
    ) -> Result<Repository, RustChainError> {
        let url = format!("{}/user/repos", self.base_url);
        debug!("Creating repository: {}", request.name);

        let body = serde_json::to_value(&request)?;
        let repository = self
            .make_request(reqwest::Method::POST, &url, Some(&body))
            .await?;
        info!("Successfully created repository: {}", request.name);
        Ok(repository)
    }

    // Issue operations
    pub async fn list_issues(
        &self,
        owner: &str,
        repo: &str,
        state: Option<IssueState>,
        per_page: Option<u32>,
    ) -> Result<Vec<Issue>, RustChainError> {
        let per_page = per_page.unwrap_or(30).min(100);
        let state_param = match state {
            Some(IssueState::Open) => "open",
            Some(IssueState::Closed) => "closed",
            Some(IssueState::All) => "all",
            None => "open",
        };

        let url = format!(
            "{}/repos/{}/{}/issues?state={}&per_page={}",
            self.base_url, owner, repo, state_param, per_page
        );
        debug!(
            "Listing issues for {}/{} with state: {}",
            owner, repo, state_param
        );

        let issues = self.make_request(reqwest::Method::GET, &url, None).await?;
        info!("Successfully listed issues for {}/{}", owner, repo);
        Ok(issues)
    }

    pub async fn get_issue(
        &self,
        owner: &str,
        repo: &str,
        issue_number: u32,
    ) -> Result<Issue, RustChainError> {
        let url = format!(
            "{}/repos/{}/{}/issues/{}",
            self.base_url, owner, repo, issue_number
        );
        debug!("Getting issue #{} from {}/{}", issue_number, owner, repo);

        let issue = self.make_request(reqwest::Method::GET, &url, None).await?;
        info!(
            "Successfully retrieved issue #{} from {}/{}",
            issue_number, owner, repo
        );
        Ok(issue)
    }

    pub async fn create_issue(
        &self,
        owner: &str,
        repo: &str,
        request: CreateIssueRequest,
    ) -> Result<Issue, RustChainError> {
        let url = format!("{}/repos/{}/{}/issues", self.base_url, owner, repo);
        debug!("Creating issue '{}' in {}/{}", request.title, owner, repo);

        let body = serde_json::to_value(&request)?;
        let issue = self
            .make_request(reqwest::Method::POST, &url, Some(&body))
            .await?;
        info!("Successfully created issue in {}/{}", owner, repo);
        Ok(issue)
    }

    pub async fn update_issue(
        &self,
        owner: &str,
        repo: &str,
        issue_number: u32,
        request: UpdateIssueRequest,
    ) -> Result<Issue, RustChainError> {
        let url = format!(
            "{}/repos/{}/{}/issues/{}",
            self.base_url, owner, repo, issue_number
        );
        debug!("Updating issue #{} in {}/{}", issue_number, owner, repo);

        let body = serde_json::to_value(&request)?;
        let issue = self
            .make_request(reqwest::Method::PATCH, &url, Some(&body))
            .await?;
        info!(
            "Successfully updated issue #{} in {}/{}",
            issue_number, owner, repo
        );
        Ok(issue)
    }

    // Pull request operations
    pub async fn list_pull_requests(
        &self,
        owner: &str,
        repo: &str,
        state: Option<PullRequestState>,
        per_page: Option<u32>,
    ) -> Result<Vec<PullRequest>, RustChainError> {
        let per_page = per_page.unwrap_or(30).min(100);
        let state_param = match state {
            Some(PullRequestState::Open) => "open",
            Some(PullRequestState::Closed) => "closed",
            Some(PullRequestState::All) => "all",
            None => "open",
        };

        let url = format!(
            "{}/repos/{}/{}/pulls?state={}&per_page={}",
            self.base_url, owner, repo, state_param, per_page
        );
        debug!(
            "Listing pull requests for {}/{} with state: {}",
            owner, repo, state_param
        );

        let prs = self.make_request(reqwest::Method::GET, &url, None).await?;
        info!("Successfully listed pull requests for {}/{}", owner, repo);
        Ok(prs)
    }

    pub async fn get_pull_request(
        &self,
        owner: &str,
        repo: &str,
        pr_number: u32,
    ) -> Result<PullRequest, RustChainError> {
        let url = format!(
            "{}/repos/{}/{}/pulls/{}",
            self.base_url, owner, repo, pr_number
        );
        debug!(
            "Getting pull request #{} from {}/{}",
            pr_number, owner, repo
        );

        let pr = self.make_request(reqwest::Method::GET, &url, None).await?;
        info!(
            "Successfully retrieved pull request #{} from {}/{}",
            pr_number, owner, repo
        );
        Ok(pr)
    }

    pub async fn create_pull_request(
        &self,
        owner: &str,
        repo: &str,
        request: CreatePullRequestRequest,
    ) -> Result<PullRequest, RustChainError> {
        let url = format!("{}/repos/{}/{}/pulls", self.base_url, owner, repo);
        debug!(
            "Creating pull request '{}' in {}/{}",
            request.title, owner, repo
        );

        let body = serde_json::to_value(&request)?;
        let pr = self
            .make_request(reqwest::Method::POST, &url, Some(&body))
            .await?;
        info!("Successfully created pull request in {}/{}", owner, repo);
        Ok(pr)
    }

    // File operations
    pub async fn get_file_content(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        ref_name: Option<&str>,
    ) -> Result<FileContent, RustChainError> {
        let mut url = format!(
            "{}/repos/{}/{}/contents/{}",
            self.base_url, owner, repo, path
        );
        if let Some(ref_val) = ref_name {
            url.push_str(&format!("?ref={}", urlencoding::encode(ref_val)));
        }
        debug!("Getting file content: {}/{}/{}", owner, repo, path);

        let file_content = self.make_request(reqwest::Method::GET, &url, None).await?;
        info!(
            "Successfully retrieved file content: {}/{}/{}",
            owner, repo, path
        );
        Ok(file_content)
    }

    pub async fn create_or_update_file(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        request: CreateOrUpdateFileRequest,
    ) -> Result<FileCommit, RustChainError> {
        let url = format!(
            "{}/repos/{}/{}/contents/{}",
            self.base_url, owner, repo, path
        );
        debug!("Creating/updating file: {}/{}/{}", owner, repo, path);

        let body = serde_json::to_value(&request)?;
        let file_commit = self
            .make_request(reqwest::Method::PUT, &url, Some(&body))
            .await?;
        info!(
            "Successfully created/updated file: {}/{}/{}",
            owner, repo, path
        );
        Ok(file_commit)
    }

    // Search operations
    pub async fn search_repositories(
        &self,
        query: &str,
        per_page: Option<u32>,
    ) -> Result<SearchResult<Repository>, RustChainError> {
        let per_page = per_page.unwrap_or(30).min(100);
        let url = format!(
            "{}/search/repositories?q={}&per_page={}",
            self.base_url,
            urlencoding::encode(query),
            per_page
        );
        debug!("Searching repositories with query: {}", query);

        let search_result = self.make_request(reqwest::Method::GET, &url, None).await?;
        info!("Successfully searched repositories with query: {}", query);
        Ok(search_result)
    }

    pub async fn search_issues(
        &self,
        query: &str,
        per_page: Option<u32>,
    ) -> Result<SearchResult<Issue>, RustChainError> {
        let per_page = per_page.unwrap_or(30).min(100);
        let url = format!(
            "{}/search/issues?q={}&per_page={}",
            self.base_url,
            urlencoding::encode(query),
            per_page
        );
        debug!("Searching issues with query: {}", query);

        let search_result = self.make_request(reqwest::Method::GET, &url, None).await?;
        info!("Successfully searched issues with query: {}", query);
        Ok(search_result)
    }

    // Comments
    pub async fn create_issue_comment(
        &self,
        owner: &str,
        repo: &str,
        issue_number: u32,
        body: &str,
    ) -> Result<Comment, RustChainError> {
        let url = format!(
            "{}/repos/{}/{}/issues/{}/comments",
            self.base_url, owner, repo, issue_number
        );
        debug!(
            "Creating comment on issue #{} in {}/{}",
            issue_number, owner, repo
        );

        let request_body = serde_json::json!({ "body": body });
        let comment = self
            .make_request(reqwest::Method::POST, &url, Some(&request_body))
            .await?;
        info!(
            "Successfully created comment on issue #{} in {}/{}",
            issue_number, owner, repo
        );
        Ok(comment)
    }

    // User operations
    pub async fn get_user(&self, username: &str) -> Result<User, RustChainError> {
        let url = format!("{}/users/{}", self.base_url, username);
        debug!("Getting user: {}", username);

        let user = self.make_request(reqwest::Method::GET, &url, None).await?;
        info!("Successfully retrieved user: {}", username);
        Ok(user)
    }

    pub async fn get_authenticated_user(&self) -> Result<User, RustChainError> {
        let url = format!("{}/user", self.base_url);
        debug!("Getting authenticated user");

        let user = self.make_request(reqwest::Method::GET, &url, None).await?;
        info!("Successfully retrieved authenticated user");
        Ok(user)
    }
}

#[async_trait]
impl Tool for GitHubClient {
    fn name(&self) -> &'static str {
        "github_client"
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![ToolCapability::Basic, ToolCapability::NetworkAccess]
    }

    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
        let operation: GitHubOperation = serde_json::from_str(input).map_err(|e| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "github_client".to_string(),
                details: format!("Invalid operation parameters: {}", e),
            })
        })?;

        match operation {
            GitHubOperation::GetRepository { owner, repo } => {
                let repository = self.get_repository(&owner, &repo).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(
                    repository,
                )?))
            }
            GitHubOperation::ListRepositories { owner, per_page } => {
                let repositories = self.list_repositories(&owner, per_page).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(
                    repositories,
                )?))
            }
            GitHubOperation::CreateRepository { request } => {
                let repository = self.create_repository(request).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(
                    repository,
                )?))
            }
            GitHubOperation::ListIssues {
                owner,
                repo,
                state,
                per_page,
            } => {
                let issues = self.list_issues(&owner, &repo, state, per_page).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(issues)?))
            }
            GitHubOperation::GetIssue {
                owner,
                repo,
                issue_number,
            } => {
                let issue = self.get_issue(&owner, &repo, issue_number).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(issue)?))
            }
            GitHubOperation::CreateIssue {
                owner,
                repo,
                request,
            } => {
                let issue = self.create_issue(&owner, &repo, request).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(issue)?))
            }
            GitHubOperation::UpdateIssue {
                owner,
                repo,
                issue_number,
                request,
            } => {
                let issue = self
                    .update_issue(&owner, &repo, issue_number, request)
                    .await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(issue)?))
            }
            GitHubOperation::ListPullRequests {
                owner,
                repo,
                state,
                per_page,
            } => {
                let prs = self
                    .list_pull_requests(&owner, &repo, state, per_page)
                    .await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(prs)?))
            }
            GitHubOperation::GetPullRequest {
                owner,
                repo,
                pr_number,
            } => {
                let pr = self.get_pull_request(&owner, &repo, pr_number).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(pr)?))
            }
            GitHubOperation::CreatePullRequest {
                owner,
                repo,
                request,
            } => {
                let pr = self.create_pull_request(&owner, &repo, request).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(pr)?))
            }
            GitHubOperation::GetFileContent {
                owner,
                repo,
                path,
                ref_name,
            } => {
                let content = self
                    .get_file_content(&owner, &repo, &path, ref_name.as_deref())
                    .await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(content)?))
            }
            GitHubOperation::CreateOrUpdateFile {
                owner,
                repo,
                path,
                request,
            } => {
                let commit = self
                    .create_or_update_file(&owner, &repo, &path, request)
                    .await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(commit)?))
            }
            GitHubOperation::SearchRepositories { query, per_page } => {
                let results = self.search_repositories(&query, per_page).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(results)?))
            }
            GitHubOperation::SearchIssues { query, per_page } => {
                let results = self.search_issues(&query, per_page).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(results)?))
            }
            GitHubOperation::CreateIssueComment {
                owner,
                repo,
                issue_number,
                body,
            } => {
                let comment = self
                    .create_issue_comment(&owner, &repo, issue_number, &body)
                    .await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(comment)?))
            }
            GitHubOperation::GetUser { username } => {
                let user = self.get_user(&username).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(user)?))
            }
            GitHubOperation::GetAuthenticatedUser => {
                let user = self.get_authenticated_user().await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(user)?))
            }
        }
    }
}

// Data structures for GitHub API

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation")]
pub enum GitHubOperation {
    #[serde(rename = "get_repository")]
    GetRepository { owner: String, repo: String },

    #[serde(rename = "list_repositories")]
    ListRepositories {
        owner: String,
        per_page: Option<u32>,
    },

    #[serde(rename = "create_repository")]
    CreateRepository { request: CreateRepositoryRequest },

    #[serde(rename = "list_issues")]
    ListIssues {
        owner: String,
        repo: String,
        state: Option<IssueState>,
        per_page: Option<u32>,
    },

    #[serde(rename = "get_issue")]
    GetIssue {
        owner: String,
        repo: String,
        issue_number: u32,
    },

    #[serde(rename = "create_issue")]
    CreateIssue {
        owner: String,
        repo: String,
        request: CreateIssueRequest,
    },

    #[serde(rename = "update_issue")]
    UpdateIssue {
        owner: String,
        repo: String,
        issue_number: u32,
        request: UpdateIssueRequest,
    },

    #[serde(rename = "list_pull_requests")]
    ListPullRequests {
        owner: String,
        repo: String,
        state: Option<PullRequestState>,
        per_page: Option<u32>,
    },

    #[serde(rename = "get_pull_request")]
    GetPullRequest {
        owner: String,
        repo: String,
        pr_number: u32,
    },

    #[serde(rename = "create_pull_request")]
    CreatePullRequest {
        owner: String,
        repo: String,
        request: CreatePullRequestRequest,
    },

    #[serde(rename = "get_file_content")]
    GetFileContent {
        owner: String,
        repo: String,
        path: String,
        ref_name: Option<String>,
    },

    #[serde(rename = "create_or_update_file")]
    CreateOrUpdateFile {
        owner: String,
        repo: String,
        path: String,
        request: CreateOrUpdateFileRequest,
    },

    #[serde(rename = "search_repositories")]
    SearchRepositories {
        query: String,
        per_page: Option<u32>,
    },

    #[serde(rename = "search_issues")]
    SearchIssues {
        query: String,
        per_page: Option<u32>,
    },

    #[serde(rename = "create_issue_comment")]
    CreateIssueComment {
        owner: String,
        repo: String,
        issue_number: u32,
        body: String,
    },

    #[serde(rename = "get_user")]
    GetUser { username: String },

    #[serde(rename = "get_authenticated_user")]
    GetAuthenticatedUser,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Repository {
    pub id: u64,
    pub name: String,
    pub full_name: String,
    pub description: Option<String>,
    pub private: bool,
    pub html_url: String,
    pub clone_url: String,
    pub ssh_url: String,
    pub language: Option<String>,
    pub stargazers_count: u32,
    pub watchers_count: u32,
    pub forks_count: u32,
    pub open_issues_count: u32,
    pub default_branch: String,
    pub created_at: String,
    pub updated_at: String,
    pub pushed_at: Option<String>,
    pub owner: User,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRepositoryRequest {
    pub name: String,
    pub description: Option<String>,
    pub private: Option<bool>,
    pub auto_init: Option<bool>,
    pub gitignore_template: Option<String>,
    pub license_template: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Issue {
    pub id: u64,
    pub number: u32,
    pub title: String,
    pub body: Option<String>,
    pub state: String,
    pub html_url: String,
    pub user: User,
    pub assignee: Option<User>,
    pub assignees: Vec<User>,
    pub labels: Vec<Label>,
    pub comments: u32,
    pub created_at: String,
    pub updated_at: String,
    pub closed_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateIssueRequest {
    pub title: String,
    pub body: Option<String>,
    pub assignees: Option<Vec<String>>,
    pub labels: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateIssueRequest {
    pub title: Option<String>,
    pub body: Option<String>,
    pub state: Option<String>,
    pub assignees: Option<Vec<String>>,
    pub labels: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PullRequest {
    pub id: u64,
    pub number: u32,
    pub title: String,
    pub body: Option<String>,
    pub state: String,
    pub html_url: String,
    pub user: User,
    pub head: PullRequestBranch,
    pub base: PullRequestBranch,
    pub mergeable: Option<bool>,
    pub merged: bool,
    pub comments: u32,
    pub commits: u32,
    pub additions: u32,
    pub deletions: u32,
    pub changed_files: u32,
    pub created_at: String,
    pub updated_at: String,
    pub closed_at: Option<String>,
    pub merged_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PullRequestBranch {
    pub label: String,
    pub ref_name: String, // renamed from 'ref' to avoid Rust keyword
    pub sha: String,
    pub user: User,
    pub repo: Repository,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePullRequestRequest {
    pub title: String,
    pub body: Option<String>,
    pub head: String,
    pub base: String,
    pub draft: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: u64,
    pub login: String,
    pub avatar_url: String,
    pub html_url: String,
    #[serde(rename = "type")]
    pub user_type: String,
    pub name: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub bio: Option<String>,
    pub location: Option<String>,
    pub public_repos: Option<u32>,
    pub public_gists: Option<u32>,
    pub followers: Option<u32>,
    pub following: Option<u32>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Label {
    pub id: u64,
    pub name: String,
    pub description: Option<String>,
    pub color: String,
    pub default: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Comment {
    pub id: u64,
    pub body: String,
    pub user: User,
    pub html_url: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileContent {
    pub name: String,
    pub path: String,
    pub sha: String,
    pub size: u32,
    #[serde(rename = "type")]
    pub file_type: String,
    pub content: String,
    pub encoding: String,
    pub download_url: Option<String>,
    pub html_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateOrUpdateFileRequest {
    pub message: String,
    pub content: String,     // Base64 encoded
    pub sha: Option<String>, // Required for updates
    pub branch: Option<String>,
    pub committer: Option<GitCommitter>,
    pub author: Option<GitCommitter>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitCommitter {
    pub name: String,
    pub email: String,
    pub date: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileCommit {
    pub content: FileContent,
    pub commit: CommitInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommitInfo {
    pub sha: String,
    pub html_url: String,
    pub author: GitCommitter,
    pub committer: GitCommitter,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResult<T> {
    pub total_count: u32,
    pub incomplete_results: bool,
    pub items: Vec<T>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum IssueState {
    #[serde(rename = "open")]
    Open,
    #[serde(rename = "closed")]
    Closed,
    #[serde(rename = "all")]
    All,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum PullRequestState {
    #[serde(rename = "open")]
    Open,
    #[serde(rename = "closed")]
    Closed,
    #[serde(rename = "all")]
    All,
}

// Helper function to create GitHub client from environment
pub fn create_github_client_from_env() -> Result<GitHubClient, RustChainError> {
    let token = std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .map_err(|_| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "github_client".to_string(),
                details: "GITHUB_TOKEN or GH_TOKEN environment variable not set".to_string(),
            })
        })?;

    let mut client = GitHubClient::new(token);

    // Support GitHub Enterprise Server
    if let Ok(base_url) = std::env::var("GITHUB_API_URL") {
        client = client.with_base_url(base_url);
    }

    Ok(client)
}

// Tool registry helper function
pub fn register_github_client(registry: &mut crate::core::tools::ToolRegistry) {
    match create_github_client_from_env() {
        Ok(client) => {
            registry.register(Box::new(client));
            info!("Registered GitHub Client");
        }
        Err(e) => {
            warn!("GitHub Client not registered: {}", e);
            debug!("To enable GitHub integration, set GITHUB_TOKEN environment variable");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_repository_request_serialization() {
        let request = CreateRepositoryRequest {
            name: "test-repo".to_string(),
            description: Some("A test repository".to_string()),
            private: Some(true),
            auto_init: Some(true),
            gitignore_template: Some("Rust".to_string()),
            license_template: Some("MIT".to_string()),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: CreateRepositoryRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.name, deserialized.name);
        assert_eq!(request.description, deserialized.description);
        assert_eq!(request.private, deserialized.private);
    }

    #[test]
    fn test_create_issue_request_serialization() {
        let request = CreateIssueRequest {
            title: "Test Issue".to_string(),
            body: Some("This is a test issue body".to_string()),
            assignees: Some(vec!["octocat".to_string()]),
            labels: Some(vec!["bug".to_string(), "help wanted".to_string()]),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: CreateIssueRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.title, deserialized.title);
        assert_eq!(request.body, deserialized.body);
        assert_eq!(request.assignees, deserialized.assignees);
        assert_eq!(request.labels, deserialized.labels);
    }

    #[test]
    fn test_github_operation_serialization() {
        let operation = GitHubOperation::GetRepository {
            owner: "octocat".to_string(),
            repo: "Hello-World".to_string(),
        };

        let json = serde_json::to_string(&operation).unwrap();
        let deserialized: GitHubOperation = serde_json::from_str(&json).unwrap();

        match deserialized {
            GitHubOperation::GetRepository { owner, repo } => {
                assert_eq!(owner, "octocat");
                assert_eq!(repo, "Hello-World");
            }
            _ => panic!("Wrong operation type deserialized"),
        }
    }

    #[test]
    fn test_issue_state_serialization() {
        let states = vec![IssueState::Open, IssueState::Closed, IssueState::All];

        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let deserialized: IssueState = serde_json::from_str(&json).unwrap();

            match (state, deserialized) {
                (IssueState::Open, IssueState::Open) => {}
                (IssueState::Closed, IssueState::Closed) => {}
                (IssueState::All, IssueState::All) => {}
                _ => panic!("State mismatch during serialization"),
            }
        }
    }

    #[test]
    fn test_search_result_deserialization() {
        let json = r#"{
            "total_count": 100,
            "incomplete_results": false,
            "items": []
        }"#;

        let result: SearchResult<Repository> = serde_json::from_str(json).unwrap();
        assert_eq!(result.total_count, 100);
        assert!(!result.incomplete_results);
        assert_eq!(result.items.len(), 0);
    }

    #[test]
    fn test_create_or_update_file_request() {
        let request = CreateOrUpdateFileRequest {
            message: "Create new file".to_string(),
            content: "SGVsbG8gV29ybGQ=".to_string(), // "Hello World" in base64
            sha: Some("abc123".to_string()),
            branch: Some("main".to_string()),
            committer: Some(GitCommitter {
                name: "Octocat".to_string(),
                email: "octocat@github.com".to_string(),
                date: None,
            }),
            author: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: CreateOrUpdateFileRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.message, deserialized.message);
        assert_eq!(request.content, deserialized.content);
        assert_eq!(request.sha, deserialized.sha);
    }

    #[test]
    fn test_github_client_creation() {
        let client = GitHubClient::new("test-token".to_string());

        assert_eq!(client.name(), "github_client");
        assert!(client.capabilities().contains(&ToolCapability::Basic));
        assert!(client
            .capabilities()
            .contains(&ToolCapability::NetworkAccess));
        assert_eq!(client.base_url, "https://api.github.com");
    }

    #[test]
    fn test_github_client_with_custom_base_url() {
        let client = GitHubClient::new("test-token".to_string())
            .with_base_url("https://api.github.enterprise.com".to_string());

        assert_eq!(client.base_url, "https://api.github.enterprise.com");
    }

    #[tokio::test]
    async fn test_invalid_operation_parameters() {
        let client = GitHubClient::new("test-token".to_string());

        let result = client.invoke("invalid json").await;
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("Invalid operation parameters"));
    }

    #[test]
    fn test_create_github_client_from_env_missing_token() {
        // Clear environment variables first
        std::env::remove_var("GITHUB_TOKEN");
        std::env::remove_var("GH_TOKEN");

        let result = create_github_client_from_env();
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("environment variable not set"));
    }

    #[test]
    fn test_github_operations_all_variants() {
        // Test that all variants can be created and serialized
        let operations = vec![
            GitHubOperation::GetRepository {
                owner: "owner".to_string(),
                repo: "repo".to_string(),
            },
            GitHubOperation::ListRepositories {
                owner: "owner".to_string(),
                per_page: Some(10),
            },
            GitHubOperation::CreateRepository {
                request: CreateRepositoryRequest {
                    name: "test".to_string(),
                    description: None,
                    private: None,
                    auto_init: None,
                    gitignore_template: None,
                    license_template: None,
                },
            },
            GitHubOperation::ListIssues {
                owner: "owner".to_string(),
                repo: "repo".to_string(),
                state: Some(IssueState::Open),
                per_page: Some(20),
            },
            GitHubOperation::GetAuthenticatedUser,
        ];

        for operation in operations {
            let json = serde_json::to_string(&operation).unwrap();
            let _deserialized: GitHubOperation = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_pull_request_state_serialization() {
        let states = vec![
            PullRequestState::Open,
            PullRequestState::Closed,
            PullRequestState::All,
        ];

        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let deserialized: PullRequestState = serde_json::from_str(&json).unwrap();

            match (state, deserialized) {
                (PullRequestState::Open, PullRequestState::Open) => {}
                (PullRequestState::Closed, PullRequestState::Closed) => {}
                (PullRequestState::All, PullRequestState::All) => {}
                _ => panic!("State mismatch during serialization"),
            }
        }
    }

    #[test]
    fn test_user_deserialization_with_type_field() {
        let json = r#"{
            "id": 1,
            "login": "octocat",
            "avatar_url": "https://github.com/images/error/octocat_happy.gif",
            "html_url": "https://github.com/octocat",
            "type": "User",
            "name": "The Octocat",
            "company": "@github",
            "email": "octocat@github.com"
        }"#;

        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.id, 1);
        assert_eq!(user.login, "octocat");
        assert_eq!(user.user_type, "User");
        assert_eq!(user.name, Some("The Octocat".to_string()));
    }

    #[test]
    fn test_create_pull_request_request() {
        let request = CreatePullRequestRequest {
            title: "New Feature".to_string(),
            body: Some("This PR adds a new feature".to_string()),
            head: "feature-branch".to_string(),
            base: "main".to_string(),
            draft: Some(true),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: CreatePullRequestRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.title, deserialized.title);
        assert_eq!(request.head, deserialized.head);
        assert_eq!(request.base, deserialized.base);
        assert_eq!(request.draft, deserialized.draft);
    }

    #[test]
    fn test_git_committer_serialization() {
        let committer = GitCommitter {
            name: "Octocat".to_string(),
            email: "octocat@github.com".to_string(),
            date: Some("2023-01-01T00:00:00Z".to_string()),
        };

        let json = serde_json::to_string(&committer).unwrap();
        let deserialized: GitCommitter = serde_json::from_str(&json).unwrap();

        assert_eq!(committer.name, deserialized.name);
        assert_eq!(committer.email, deserialized.email);
        assert_eq!(committer.date, deserialized.date);
    }
}
