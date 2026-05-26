package com.codereview.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.codereview.model.CodeReviewResult;
import com.codereview.model.ReviewRequest;
import com.codereview.service.CodeReviewService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * REST controller for code review operations.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/review")
@RequiredArgsConstructor
public class CodeReviewController {

    private final CodeReviewService codeReviewService;

    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CodeReviewResult> reviewRepository(@Valid @RequestBody ReviewRequest request) {
        log.info("Received review request for repository: {}", request.getRepositoryUrl());

        if (!codeReviewService.isReviewEnabled(request)) {
            log.info("Code review is disabled");
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(CodeReviewResult.builder()
                            .repositoryUrl(request.getRepositoryUrl())
                            .status(CodeReviewResult.ReviewStatus.DISABLED)
                            .build());
        }

        CodeReviewResult result = codeReviewService.reviewRepository(request);
        return ResponseEntity.ok(result);
    }

    @GetMapping(value = "/status", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ReviewServiceStatus> getStatus() {
        return ResponseEntity.ok(new ReviewServiceStatus(
                codeReviewService.isEnabled(),
                "Code Review Service is " + (codeReviewService.isEnabled() ? "enabled" : "disabled")
        ));
    }

    public record ReviewServiceStatus(boolean enabled, String message) {}
}
