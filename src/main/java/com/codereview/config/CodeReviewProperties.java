package com.codereview.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Validated
@ConfigurationProperties(prefix = "codereview")
public class CodeReviewProperties {

    /**
     * Master switch to enable/disable the entire code review functionality
     */
    private boolean enabled = true;

    @NotNull
    private GitHubConfig github = new GitHubConfig();

    @NotNull
    private AnalysisConfig analysis = new AnalysisConfig();

    @Data
    public static class GitHubConfig {
        private String token;
        private String apiUrl = "https://api.github.com";
        private String cloneDirectory;
    }

    @Data
    public static class AnalysisConfig {
        private RuleConfig sonarqubeRules = new RuleConfig();
        private RuleConfig vulnerabilityScan = new RuleConfig();
        private List<String> supportedExtensions = List.of(".java", ".xml", ".properties", ".yml", ".yaml");
        private List<String> exclusions = List.of("target/", "build/", ".git/", ".idea/", "node_modules/");

        @Data
        public static class RuleConfig {
            private boolean enabled = true;
        }
    }
}
