package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.config.SecurityUtil;
import com.zuehlke.securesoftwaredevelopment.domain.Person;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.repository.PersonRepository;
import com.zuehlke.securesoftwaredevelopment.repository.RoleRepository;
import com.zuehlke.securesoftwaredevelopment.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.nio.file.AccessDeniedException;
import java.sql.SQLException;
import java.util.List;
import java.util.Objects;

@Controller
public class PersonsController {

    private final PersonRepository personRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    private static final Logger LOG = LoggerFactory.getLogger(PersonsController.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(PersonsController.class);

    public PersonsController(PersonRepository personRepository, UserRepository userRepository, RoleRepository roleRepository) {
        this.personRepository = personRepository;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @GetMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('VIEW_PERSON') || hasAuthority('UPDATE_PERSON')")
    public String person(@PathVariable int id, Model model, HttpSession session) throws AccessDeniedException{

        int currentUserId = Objects.requireNonNull(SecurityUtil.getCurrentUser()).getId();
        boolean currentUserIsNotAdmin = roleRepository.findByUserId(currentUserId)
                .stream().noneMatch(role -> role.getName().equals("ADMIN"));

        if(currentUserIsNotAdmin && currentUserId != id){
            LOG.error("Access denied! User " + SecurityUtil.getCurrentUser().getUsername() + " does not have necessary permissions to update person details.");
            throw new AccessDeniedException("Access denied!");
        }

        String csrfToken = session.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", csrfToken);
        model.addAttribute("person", personRepository.get("" + id));
        return "person";
    }

    @GetMapping("/myprofile")
    @PreAuthorize("hasAuthority('VIEW_MY_PROFILE')")
    public String self(Model model, Authentication authentication, HttpSession session) {
        String csrfToken = session.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", csrfToken);
        User user = (User) authentication.getPrincipal();
        model.addAttribute("person", personRepository.get("" + user.getId()));
        return "person";
    }

    @DeleteMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public ResponseEntity<Void> person(@PathVariable int id) throws AccessDeniedException  {

        int currentUserId = Objects.requireNonNull(SecurityUtil.getCurrentUser()).getId();
        boolean currentUserIsNotAdmin = roleRepository.findByUserId(currentUserId)
                .stream().noneMatch(role -> role.getName().equals("ADMIN"));

        if(currentUserIsNotAdmin && currentUserId != id){
            LOG.error("Access denied! User " + SecurityUtil.getCurrentUser().getUsername() + " does not have necessary permissions to update person details.");
            throw new AccessDeniedException("Access denied!");
        }

        personRepository.delete(id);
        userRepository.delete(id);

        auditLogger.audit("Person deleted successfully, personId: " + id + " by: " + SecurityUtil.getCurrentUser().getUsername());

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/update-person")
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public String updatePerson(Person person, HttpSession session, @RequestParam("csrfToken") String csrfToken) throws AccessDeniedException {

        String sessionToken = session.getAttribute("CSRF_TOKEN").toString();

        if(!csrfToken.equals(sessionToken)){
            LOG.error("Access denied! User " + SecurityUtil.getCurrentUser().getUsername() + " does not have necessary permissions to update person details.");
            throw new AccessDeniedException("Access denied!");
        }

        int currentUserId = Objects.requireNonNull(SecurityUtil.getCurrentUser()).getId();
        boolean currentUserIsNotAdmin = roleRepository.findByUserId(currentUserId)
                .stream().noneMatch(role -> role.getName().equals("ADMIN"));

        if(currentUserIsNotAdmin && currentUserId != Integer.parseInt(person.getId())){
            LOG.error("Access denied! User " + SecurityUtil.getCurrentUser().getUsername() + " does not have necessary permissions to update person details.");
            throw new AccessDeniedException("Access denied!");
        }

        personRepository.update(person);

        auditLogger.audit("Person updated successfully, personId: " + person.getId() + " by: " + SecurityUtil.getCurrentUser().getUsername());

        return "redirect:/persons/" + person.getId();
    }

    @GetMapping("/persons")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public String persons(Model model) {
        model.addAttribute("persons", personRepository.getAll());
        return "persons";
    }

    @GetMapping(value = "/persons/search", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public List<Person> searchPersons(@RequestParam String searchTerm) throws SQLException {
        return personRepository.search(searchTerm);
    }
}
