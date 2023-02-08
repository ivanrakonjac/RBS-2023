package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.config.SecurityUtil;
import com.zuehlke.securesoftwaredevelopment.domain.Rating;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.repository.RatingRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
public class RatingsController {

    private RatingRepository ratingRepository;
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(RatingsController.class);

    public RatingsController(RatingRepository ratingRepository) {
        this.ratingRepository = ratingRepository;
    }

    @PostMapping(value = "/ratings", consumes = "application/json")
    @PreAuthorize("hasAuthority('RATE_MOVIE')")
    public String createOrUpdateRating(@RequestBody Rating rating, Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        rating.setUserId(user.getId());
        ratingRepository.createOrUpdate(rating);

        auditLogger.audit("Rating successfully added, movie:" + rating.getMovieId() + " rating:" + rating.getRating() + " by user: " + SecurityUtil.getCurrentUser().getUsername());

        return "redirect:/movies?id=" + rating.getMovieId();
    }
}
