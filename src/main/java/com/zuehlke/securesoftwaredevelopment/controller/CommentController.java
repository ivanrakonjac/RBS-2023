package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.domain.Comment;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.repository.CommentRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
public class CommentController {

    private CommentRepository commentRepository;
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(CommentController.class);

    public CommentController(CommentRepository commentRepository) {
        this.commentRepository = commentRepository;
    }

    @PostMapping(value = "/comments", consumes = "application/json")
    @PreAuthorize("hasAuthority('ADD_COMMENT')")
    public ResponseEntity<Void> createComment(@RequestBody Comment comment, Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        comment.setUserId(user.getId());
        commentRepository.create(comment);

        auditLogger.audit("Comment added, commentId" + comment.getComment() + " by user:" + comment.getUserId());

        return ResponseEntity.noContent().build();
    }
}
