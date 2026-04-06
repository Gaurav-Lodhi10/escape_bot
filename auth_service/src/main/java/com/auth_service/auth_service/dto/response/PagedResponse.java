package com.auth_service.auth_service.dto.response;


import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;
import org.springframework.data.domain.Page;

import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Generic pagination wrapper — wraps Spring's Page<T> into a clean JSON shape.
 *
 * Usage:
 *   Page<User> page = userRepository.findAll(pageable);
 *   PagedResponse<UserSummaryResponse> response =
 *       PagedResponse.of(page, user -> toSummary(user));
 */
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PagedResponse<T> {

    private List<T> content;
    private int page;           // 0-based current page
    private int size;           // page size requested
    private long totalElements; // total records in DB matching the query
    private int totalPages;
    private boolean first;
    private boolean last;

    public static <E, D> PagedResponse<D> of(Page<E> page, Function<E, D> mapper) {
        return PagedResponse.<D>builder()
                .content(page.getContent().stream().map(mapper).collect(Collectors.toList()))
                .page(page.getNumber())
                .size(page.getSize())
                .totalElements(page.getTotalElements())
                .totalPages(page.getTotalPages())
                .first(page.isFirst())
                .last(page.isLast())
                .build();
    }
}
